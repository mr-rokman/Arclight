using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace Arclight
{
    public static partial class DKIM // aka RFC 6376, https://datatracker.ietf.org/doc/html/rfc6376/
    {
        public enum CipherKind : ushort { Unknown = 0, RSA = 1 }

        public enum HashKind : ushort { Unknown = 0, SHA1 = 1, SHA256 = 2 }

        public enum SignatureAlgorithm
        {
            Unknown = 0,    
            Sha1RSA = 1,
            Sha256RSA = 2
            // TODO Ed25519
        }

        public enum SignerPolicy : ushort // TODO имя сосёт. содержимое тоже
        {
            Default = 0,
            Testing = 1,
            Strict = 2
        }

        public static class Encoding
        {
            public static string ToQuotedPrintable(string Input) { return ToQuotedPrintable(Input, false); }
            public static string ToQuotedPrintable(string Input, bool EncodeAllCharacters)
            {
                StringBuilder rv; System.Text.Encoding enc = new System.Text.UTF8Encoding();
                char[] cb; byte[] bb; int i, j, k;

                bb = new byte[16]; cb = Input.ToCharArray();
                rv = new StringBuilder(bb.Length * 3); // maximum

                for (i = 0; i < cb.Length; ++i)
                {
                    if (EncodeAllCharacters || (cb[i] < 0x20 || cb[i] > 0x7F || cb[i] == 0x20 || cb[i] == 0x3B || char.IsWhiteSpace(cb[i]) || cb[i] == '\n' || cb[i] == '\r'))
                    {
                        j = enc.GetByteCount(cb, i, 1); // variable-length shenanigans
                        enc.GetBytes(cb, i, 1, bb, 0);

                        for (k = 0; k < j; ++k) { rv.Append('='); rv.Append(Utils.Conversion.ToHexString(bb[k], true)); };
                    }
                    else rv.Append(cb[i]);
                };

                return rv.ToString();
            }

            public static string FromDKIMQuotedPrintable(string Input)
            {
                int i, c = 0;
                byte[] bb;

                if (Input == null || Input.Length == 0) return string.Empty;

                bb = new byte[Input.Length];

                for (i = 0; i < Input.Length; ++i)
                {
                    if (char.IsWhiteSpace(Input[i])) continue; // ignore

                    if (Input[i] == '=') // encoded
                    {
                        if (Input.Length - i - 1 < 2) throw new ArgumentException("Malformed data");

                        bb[c] = byte.Parse(Input.Substring(i + 1, 1) + Input.Substring(i + 2, 1), System.Globalization.NumberStyles.HexNumber);
                        ++c; i += 2;
                    }
                    else { bb[c] = (byte)Input[i]; ++c; }; // as is
                };

                return System.Text.UTF8Encoding.UTF8.GetString(bb, 0, c);
            }

            public static System.Text.Encoding GetEncodingFromHeaders(string Message)
            {
                System.Text.Encoding rv;
                string sb = null;
                string[] tok; int i, j;
                int nb = 0;

                try
                {
                    while(true)
                    {
                        _adjust_header(ref Message, "content-type", nb, ref sb, null, false, false);
                        if (sb == null || sb.Length == 0) break;

                        tok = sb.Split(';');
                        for (i = 0; i < tok.Length; ++i)
                        {
                            j = tok[i].IndexOf('=');

                            if (i > 0 && tok[i].Substring(0, j).Trim().ToLower() == "charset")
                            {
                                rv = System.Text.Encoding.GetEncoding(tok[i].Substring(j + 1).Replace('"', ' ').Trim());

                                return rv;
                            };
                        };

                        ++nb;
                    };

                    return System.Text.Encoding.ASCII;
                }
                catch { return System.Text.Encoding.ASCII; };
            }
            public static System.Text.Encoding GetEncodingFromHeaders(string[] Headers)
            {
                System.Text.Encoding rv;
                string[] tok; int i, j, k;

                try
                {
                    for (i = 0; i < Headers.Length; ++i)
                    {
                        k = Headers[i].IndexOf(':');

                        if (Headers[i].Substring(0, k).Trim().ToLower() == "content-type")
                        {
                            tok = Headers[i].Substring(k + 1).Split(';');

                            for (j = 0; j < tok.Length; ++j)
                            {
                                k = tok[j].IndexOf('=');

                                if (k > 0 && tok[j].Substring(0, k).Trim().ToLower() == "charset")
                                {
                                    rv = System.Text.Encoding.GetEncoding(tok[j].Substring(k + 1).Replace('"', ' ').Trim());

                                    return rv;
                                };
                            };
                        };
                    };

                    return System.Text.Encoding.ASCII;
                }
                catch { return System.Text.Encoding.ASCII; };
            }

            public static string DecodeMessage(byte[] StreamData, ref System.Text.Encoding DetectedBodyEncoding)
            {
                int i;
                string sb1, sb2;
                int nb1 = -1, nb2 = 0;
                string[] ln = null, lt = null;
                StringBuilder rv; System.Text.Encoding iv;

                if (StreamData == null || StreamData.Length == 0) return null;
                sb1 = System.Text.Encoding.ASCII.GetString(StreamData);

                _break_lines(ref sb1, ref ln, ref lt, true, false, false);

                // find header boundary
                for (i = 0; i < ln.Length; ++i)
                {
                    if (ln[i] == null || ln[i].Length == 0) { nb1 = i - 1; break; };
                };

                if (nb1 == -1 && i > 0) nb1 = ln.Length - 1;

                rv = new StringBuilder(StreamData.Length);

                // output headers & compute byte offset
                for (i = 0; i <= nb1; ++i)
                {
                    rv.Append(ln[i]); rv.Append(lt[i]);

                    nb2 += ln[i].Length + lt[i].Length;
                };

                if (nb1 < ln.Length - 1)
                {
                    nb2 += ln[nb1 + 1].Length + lt[nb1 + 1].Length; // boundary, should always be 0 + 2 bytes
                    //Array.Resize<string>(ref ln, nb1 + 1); Array.Resize<string>(ref lt, ln.Length); // strip excess lines

                    iv = DKIM.Encoding.GetEncodingFromHeaders(rv.ToString()); // detect body encoding
                    DetectedBodyEncoding = iv;

                    if (StreamData.Length - nb2 <= 0) sb2 = string.Empty; // body is empty
                    else sb2 = iv.GetString(StreamData, nb2, StreamData.Length - nb2); // decode body using encoding from headers (or fallback to ascii)

                    rv.Append(lt[nb1 + 1]); // boundary
                    rv.Append(sb2); // decoded body

                    return rv.ToString();
                }
                else return rv.ToString(); // body is missing
            }
            public static string DecodeMessage(byte[] StreamData)
            {
                System.Text.Encoding iv = null;

                return DecodeMessage(StreamData, ref iv); // suppress iv
            }
        }

        public static class Canonicalization
        {
            public enum Algorithm
            {                
                Simple = 0,
                Relaxed = 1
            }

            public static string[] GetCanonicalHeaders(ref string NormalizedMessage, Algorithm Algorithm)
            {
                string[] rv; int rvc = 0;
                string[] ln = null, lt = null; int li = 0, li_max = -1;
                string hk = null, hv = null;
                int nb1; bool f = false;

                if (NormalizedMessage == null || NormalizedMessage.Length == 0) throw new ArgumentException("No header data");

                rv = new string[16]; // estimate

                _break_lines(ref NormalizedMessage, ref ln, ref lt, true, true, true);
                if (ln == null || lt == null) throw new ArgumentException("No header data");

                // where are them headers??
                for (li = 0; li < ln.Length; ++li)
                {
                    if (ln[li] == null || ln[li].Length == 0) { li_max = li - 1; break; }; // there they are
                };

                if (li_max == -1 && li > 0) li_max = ln.Length - 1; // tricky - assume input is only headers

                for (li = 0; li <= li_max; ++li)
                {
                    if ((!char.IsWhiteSpace(ln[li][0]) && hk != null && hk.Length > 0) || li == li_max) // new header after continuation | last line
                    {
                        if (li == li_max && char.IsWhiteSpace(ln[li][0])) // append last continuation
                        {
                            if (Algorithm == Algorithm.Relaxed) hk += ln[li]; // += without lt
                            else if (Algorithm == Algorithm.Simple) hk += (lt[li - 1] + ln[li]); // with lt from prev line
                        }
                        else if (li == li_max && !char.IsWhiteSpace(ln[li][0]))
                        {
                            if (hk == null || hk.Length == 0) hk = ln[li]; // last header
                            else f = true; // second to last header (set rewind flag)
                        };

                        if (Algorithm == Algorithm.Relaxed)
                        {
                            nb1 = hk.IndexOf(':'); if (nb1 < 1) throw new ArgumentException("Malformed header data");

                            hv = hk.Substring(nb1 + 1, hk.Length - nb1 - 1); hk = hk.Substring(0, nb1); // split k & v

                            // modify as mandated
                            _compact_wsp(ref hv, true);
                            hk = hk.ToLower().TrimEnd(); hv = hv.TrimStart();

                            if (rv == null || rv.Length < (rvc + 1)) { Array.Resize<string>(ref rv, rv.Length + 50); }; // grow rv

                            rv[rvc] = hk + ':' + hv; ++rvc; // reassemble
                        }
                        else if (Algorithm == Algorithm.Simple) // as is
                        {
                            if (rv == null || rv.Length < (rvc + 1)) { Array.Resize<string>(ref rv, rv.Length + 50); }; // grow rv

                            rv[rvc] = hk; ++rvc; // copy as is
                        }
                        else throw new ArgumentException("Unknown algorithm");

                        hk = null; hv = null;
                        if (li < li_max || f) --li; f = false; // step back (& clear rewind flag)
                    }
                    else if (char.IsWhiteSpace(ln[li][0]) && hk != null && hk.Length > 0) // folded line continuation
                    {
                        if (Algorithm == Algorithm.Relaxed) hk += ln[li]; // += without lt
                        else if (Algorithm == Algorithm.Simple) hk += (lt[li - 1] + ln[li]); // with lt from prev line
                    }
                    else if (char.IsWhiteSpace(ln[li][0]) && hk == null && hk.Length == 0) throw new ArgumentException("Malformed header data"); // some bullshit
                    else // begin new header
                    {
                        hk = ln[li]; hv = null;
                    };
                };

                if (rv.Length != rvc) { Array.Resize<string>(ref rv, rvc); };

                return rv;
            }

            public static string GetCanonicalHeader(string SingleHeader, Algorithm Algorithm, bool IncludeLineTerminator) // if input contains multiple headers, all entries except first will be discarded
            {
                string[] iv; string rv;

                iv = GetCanonicalHeaders(ref SingleHeader, Algorithm);
                if (iv == null || iv.Length == 0) return string.Empty;
                else rv = iv[0];

                if (!IncludeLineTerminator) // strip lt if present
                {
                    if ((rv[rv.Length - 2] == '\r' && rv[rv.Length - 1] == '\n') || (rv[rv.Length - 2] == '\n' && rv[rv.Length - 1] == '\r')) rv = rv.Substring(0, rv.Length - 2);
                    else if ((rv[rv.Length - 1] == '\r') || (rv[rv.Length - 1] == '\n')) rv = rv.Substring(0, rv.Length - 1);
                };

                return rv;
            }

            public static string GetCanonicalBody(ref string NormalizedMessage, Algorithm Algorithm)
            {
                StringBuilder rv;
                string[] ln = null, lt = null; int li = 0, li_min = -1;
                int nb1 = 0;

                rv = new StringBuilder((int)NormalizedMessage.Length + 1); // estimate

                _break_lines(ref NormalizedMessage, ref ln, ref lt, true, false, false);

                // where are them bodies??
                for (li = 0; li < ln.Length; ++li)
                {
                    if (ln[li] == null || ln[li].Length == 0) { li_min = li + 1; break; }; // there they are
                };

                // no body at all
                if ((li_min == -1 || ln == null || ln.Length == 0) && Algorithm == Algorithm.Simple)
                {
                    rv.Append('\r'); rv.Append('\n');
                    return rv.ToString();
                }
                else if ((li_min == -1 || ln == null || ln.Length == 0) && Algorithm == Algorithm.Relaxed)
                {
                    return string.Empty;
                };

                if (Algorithm == Algorithm.Relaxed) // rtrim + compact wsp in line (for non-blanks)
                {
                    for (li = li_min; li <= ln.Length - 1; ++li)
                    {
                        if (ln != null && ln.Length > 0) // for non-blanks only
                        {
                            _compact_wsp(ref ln[li], true); // compact wsp

                            ln[li] = ln[li].TrimEnd(); // rtrim
                        };
                    };
                };

                if (Algorithm == Algorithm.Simple || Algorithm == Algorithm.Relaxed) // blanks at end
                {
                    nb1 = 0; // blanks counter
                    for (li = (ln == null ? -1 : ln.Length) - 1; li >= li_min; --li)
                    {
                        if (ln[li] == null || ln[li].Length == 0) ++nb1;
                        else break;
                    };
                };

                // write output
                if (nb1 == ln.Length) // all blanks
                {
                    rv.Append('\r'); rv.Append('\n'); // <...> If the body is non-empty but does not end with a CRLF, a CRLF is added. <...>
                }
                else
                {
                    for (li = li_min; li <= (ln.Length - 1) - nb1; ++li) // omit blanks, write the rest
                    {
                        rv.Append(ln[li]); // line ...

                        if ((li == (ln.Length - 1) - nb1) && (lt[li] == null || lt[li].Length == 0)) rv.Append("\r\n"); // ... + lt (or CRLF is missing)
                        else rv.Append(lt[li]);
                    };
                };

                return rv.ToString();
            }
        }

        public partial class Signer
        {
            public enum Option : short
            {
                RemoveExistingSignatures = -1,
                Default = 0,
                SignExistingSignatures = 1
            }

            public class HeaderOption
            {
                public enum Trait : ushort
                {
                    None = 0,
                    SignAllOccurences = 1,
                    SignEmptyValue = 2, // mutually ...
                    OmitIfMissing = 4 // ... exclusive
                }

                public string Name;
                public Trait Traits;

                public HeaderOption(string HeaderName, Trait Options) { Name = HeaderName; Traits = Options; }
            }

            public class HeaderOptionList : List<HeaderOption>
            {
                protected string[] unique_k;
                protected int[] unique_v;

                public new void Add(HeaderOption Item) // uniqueness check
                {
                    int i;

                    if (unique_k == null || unique_v == null || unique_k.Length != this.Count || unique_v.Length != this.Count)
                    {
                        unique_k = new string[this.Count]; unique_v = new int[unique_k.Length];

                        for (i = 0; i < unique_k.Length; ++i) { unique_k[i] = this[i].Name.Trim().ToLower(); unique_v[i] = i; };

                        Array.Sort(unique_k, unique_v);
                    };

                    i = -1;
                    i = Array.BinarySearch<string>(unique_k, Item.Name.Trim().ToLower());

                    if (i < 0) base.Add(Item); // add new unique header option
                    else // copy traits into existing header option
                    {
                        this[i].Traits = Item.Traits;
                    };
                }
                public new void AddRange(IEnumerable<HeaderOption> collection) { foreach (HeaderOption item in collection) this.Add(item); }

                public new bool Remove(HeaderOption item) { unique_k = null; unique_v = null; return base.Remove(item); }
                public new int RemoveAll(Predicate<HeaderOption> match) { unique_k = null; unique_v = null; return base.RemoveAll(match); }
                public new void RemoveAt(int index) { unique_k = null; unique_v = null; base.RemoveAt(index); }
                public new void RemoveRange(int index, int count) { unique_k = null; unique_v = null; base.RemoveRange(index, count); }
                public new void Clear() { unique_k = null; unique_v = null; base.Clear(); }

                public HeaderOptionList() : base() { }
                public HeaderOptionList(int capacity) : base(capacity) { }
                public HeaderOptionList(IEnumerable<HeaderOption> collection) : base(collection) { }
            }

            protected string _auid;
            protected string _domain_explicit;
            protected string _domain_implicit;
            protected string _selector;
            protected CipherKind _pvk_kind;
            protected RSAParameters _pvk_rsa;
            protected SignatureAlgorithm _sign_algo;
            protected HeaderOptionList _headopts;
            protected ulong _bodylen;
            protected bool _ts;
            protected TimeSpan _sign_val_span;
            protected Canonicalization.Algorithm _head_can_algo;
            protected Canonicalization.Algorithm _body_can_algo;
            protected bool _dsig_verbose;
            protected bool _sign_all_head;

            public Signer() : this(true) { }
            public Signer(bool IncludeDefaultHeaders)
            {
                _body_can_algo = Canonicalization.Algorithm.Relaxed; _head_can_algo = Canonicalization.Algorithm.Relaxed;

                if (IncludeDefaultHeaders)
                {
                    _headopts = new HeaderOptionList();
                    _headopts.Add(new HeaderOption("from", HeaderOption.Trait.SignEmptyValue)); // only this mandated by rfc
                    _headopts.Add(new HeaderOption("reply-to", HeaderOption.Trait.OmitIfMissing));
                    _headopts.Add(new HeaderOption("subject", HeaderOption.Trait.OmitIfMissing));
                    _headopts.Add(new HeaderOption("date", HeaderOption.Trait.OmitIfMissing));
                    _headopts.Add(new HeaderOption("to", HeaderOption.Trait.OmitIfMissing));
                    _headopts.Add(new HeaderOption("cc", HeaderOption.Trait.OmitIfMissing));
                };

                _sign_all_head = false;
            }

            ~Signer()
            {
                clear_keys();
            }           

            public string PublicRecord
            {
                get
                {
                    try
                    {
                        if (_pvk_kind == CipherKind.RSA)
                        {
                            return ComposePublicRecord(Utils.Cryptography.RSA.ParamsToAsn1Der(_pvk_rsa, false), SignerPolicy.Default, this.SignatureAlgorithm);
                        }
                        else throw new Exception();
                    }
                    catch { return string.Empty; };
                }
            }

            public bool SignAllHeaders { get { return _sign_all_head; } set { _sign_all_head = value; } } // not recommended but what the hell

            public bool IncludeOptionalParameters { get { return _dsig_verbose; } set { _dsig_verbose = value; } } // aka verbose dsig
            
            public string AgentID
            {
                get { return (_auid == null || _auid.Length == 0 ? string.Empty : _auid); }
                set { _auid = value; }
            }

            public string DomainName
            {
                get { return (_domain_explicit == null || _domain_explicit.Length == 0 ? string.Empty : _domain_explicit); }
                set { if (value == null || value.Length == 0) _domain_explicit = null; else _domain_explicit = value.Trim(); }
            }

            public string SelectorName
            {
                get { return (_selector == null || _selector.Length == 0 ? string.Empty : _selector); }
                set { if (value == null || value.Length == 0) _selector = null; else _selector = value.Trim(); }
            }

            public byte[] PrivateKeyDER
            {
                set
                {
                    try { _pvk_rsa = Utils.Cryptography.RSA.Asn1DerToParams(value); _pvk_kind = CipherKind.RSA; /* TODO test keypair */ return;  }
                    catch { }

                    // TODO other key types (ecc, edwards etc)
                    _pvk_kind = CipherKind.Unknown;
                    clear_keys();

                    throw new ArgumentException("Unrecognized data");
                }
            }
            public string PrivateKeyBase64
            {
                set
                {
                    try { _pvk_rsa = Utils.Cryptography.RSA.Base64ToParams(value); _pvk_kind = CipherKind.RSA; /* TODO test keypair */ return; }
                    catch { }

                    // TODO other key types (ecc, edwards etc)
                    _pvk_kind = CipherKind.Unknown;
                    clear_keys();

                    throw new ArgumentException("Unrecognized data");
                }
            }
            public bool IsPrivateKeyPresent
            {
                get { if (_pvk_kind == CipherKind.RSA && true /* TODO test key */) return true; else return false; } // TODO ecc/ed
            }

            public SignatureAlgorithm SignatureAlgorithm // TODO clear existing key on keytype change (when ecc/ed will be implemented)
            {
                get
                {
                    if (_pvk_kind == CipherKind.RSA && (_sign_algo == SignatureAlgorithm.Sha1RSA || _sign_algo == SignatureAlgorithm.Sha256RSA)) return _sign_algo;
                    else return SignatureAlgorithm.Unknown;
                }
                set
                {
                    if (value == SignatureAlgorithm.Unknown)
                    {
                        _pvk_kind = CipherKind.Unknown;
                        _pvk_rsa = new RSAParameters();
                        return;
                    }
                    else if ((value == SignatureAlgorithm.Sha1RSA || value == SignatureAlgorithm.Sha256RSA) && _pvk_kind == CipherKind.RSA) _sign_algo = value;
                    else return; // set pvk first
                }
            }

            public HeaderOptionList HeaderOptions
            {
                get { if (_headopts == null) _headopts = new HeaderOptionList(); return _headopts; }
                set
                {
                    if (_headopts == null) _headopts = new HeaderOptionList(value);
                    else _headopts = value;
                }
            }

            public ulong BodyLengthLimit { get { return _bodylen; } set { _bodylen = value; } }
            public bool IsBodyLengthLimited { get { return (_bodylen == 0 ? false : true); } }

            public TimeSpan SignatureValidityPeriod { get { return _sign_val_span; } set { _sign_val_span = value; } }
            public bool IsSignatureTimeLimited { get { return (_sign_val_span == TimeSpan.Zero ? false : true); } }

            public bool EnableTimestamping{ get { return _ts; } set { _ts = value; } }

            public Canonicalization.Algorithm HeaderCanonicalization { get { return _head_can_algo; } set { _head_can_algo = value; } }
            public Canonicalization.Algorithm BodyCanonicalization { get { return _body_can_algo; } set { _body_can_algo = value; } }           

            public string SignMessage(Stream NormalizedMessage) { return SignMessage(NormalizedMessage, Option.Default); }
            public string SignMessage(Stream NormalizedMessage, Option Options)
            {
                byte[] bb; string msg;
    
                if (NormalizedMessage == null || !NormalizedMessage.CanRead || !NormalizedMessage.CanSeek || NormalizedMessage.Length == 0) throw new ArgumentException("No data");

                bb = new byte[NormalizedMessage.Length]; NormalizedMessage.Seek(0, SeekOrigin.Begin);
                NormalizedMessage.Read(bb, 0, bb.Length);
                msg = System.Text.Encoding.ASCII.GetString(bb);
                bb = null;

                return SignMessage(msg, Options);
            }
            public string SignMessage(string NormalizedMessage) { return SignMessage(NormalizedMessage, Option.Default); }
            public string SignMessage(string NormalizedMessage, Option Options) // main routine
            {
                string sv = null; // suppress iv

                return _sign_routine(NormalizedMessage, Options, ref sv);
            }

            public string ComputeSignature(string NormalizedMessage) { return ComputeSignature(NormalizedMessage, Option.Default); }
            public string ComputeSignature(string NormalizedMessage, Option Options)
            {
                string rv = string.Empty;

                _sign_routine(NormalizedMessage, Option.Default, ref rv);

                return rv;
            }
        }

        public partial class Verifier
        {
            public struct Result
            {
                public enum Code { SUCCESS, PERMFAIL, TEMPFAIL }
                public enum ExtendedCode : short
                { 
                    NoSignature = -1,

                    None = 0,

                    NoPublicRecord = 1,
                    MalformedPublicRecord = 2, 
                    MalformedSignature = 3,
                    UnacceptablePublicRecord = 4,
                    RevokedKey = 5,
                    CipherAlgorithmMismatch = 6,
                    HashAlgorithmMismatch = 7,
                    BodyTampered = 8,
                    MessageTampered = 9,
                    TimestampInFuture = 10,
                    SignatureExpired = 11,
                    PolicyViolation = 12
                }

                public Code PrimaryCode;
                public ExtendedCode SecondaryCode;
                public string Information;
                public ulong ElapsedMillis;
            }

            public class HeaderOption
            {
                public string Name;
                public ushort ReverseOrdinal;

                public HeaderOption(string HeaderName, ushort ReverseOrdinal) { this.Name = HeaderName; this.ReverseOrdinal = ReverseOrdinal; }
            }

            protected CipherKind _pbk_kind;
            protected RSAParameters _pbk_rsa;
            protected HashKind _hash_algo;
            protected SignerPolicy _signpol;
            protected string _pr_note; // for lulz

            public Verifier() { }
            public Verifier(string Domain, string Selector) : this(Selector + "._domainkey." + Domain) { }
            public Verifier(string PublicRecord) // address | txt-data
            {
                string iv;

                if (PublicRecord == null || PublicRecord.Length == 0) throw new ArgumentException("No data");
                else iv = PublicRecord.Trim();

                if (iv.Length >= 8 && iv.Substring(0, 8).ToLower() == "v=dkim1;") // public record data
                {
                    // ???
                }
                else // try to retrieve record data
                {
                    try { iv = new List<string>(Utils.SystemDns.GetTxtRecords(iv))[0]; }
                    catch { throw new ArgumentException("Unable to retrieve DKIM public record data"); };
                };

                CipherKind a = CipherKind.Unknown;
                byte[] p = null;
                this._pr_note = null;

                this._parse_pr(iv, ref a, ref p, ref this._signpol, ref this._hash_algo, ref this._pr_note);
                if (p != null && p.Length > 0) this.PublicKeyDER = p;
            }

            ~Verifier() { }

            public string PublicKeyBase64
            {
                get { if (_pbk_kind == CipherKind.RSA) return Utils.Cryptography.RSA.ParamsToBase64(_pbk_rsa, false); else return string.Empty; }
                set
                {
                    try { _pbk_rsa = Utils.Cryptography.RSA.Base64ToParams(value); _pbk_kind = CipherKind.RSA; return; }
                    catch { }

                    // TODO other key types (ecc, edwards etc)
                    _pbk_kind = CipherKind.Unknown;

                    if (value != null && value.Length > 0) throw new ArgumentException("Unrecognized data"); // no throw on null - revoked key
                }
            }
            
            public byte[] PublicKeyDER
            {
                get { if (_pbk_kind == CipherKind.RSA) return Utils.Cryptography.RSA.ParamsToAsn1Der(_pbk_rsa, false); else return null; }
                set
                {
                    try { _pbk_rsa = Utils.Cryptography.RSA.Asn1DerToParams(value); _pbk_kind = CipherKind.RSA; return; }
                    catch { }

                    // TODO other key types (ecc, edwards etc)
                    _pbk_kind = CipherKind.Unknown;

                    if (value != null && value.Length > 0) throw new ArgumentException("Unrecognized data"); // no throw on null - revoked key
                }
            }

            public Result VerifyMessage(string NormalizedMessage) { return VerifyMessage(NormalizedMessage, true); }
            public Result VerifyMessage(string NormalizedMessage, bool RequeryPublicRecord)
            {
                Result rv = new Result();
                string[] ch; int i;

                ch = Canonicalization.GetCanonicalHeaders(ref NormalizedMessage, Canonicalization.Algorithm.Simple); // get intact headers

                for (i = 0; i < ch.Length; ++i) // find first dsig
                {
                    if (ch[i].Substring(0, ch[i].IndexOf(':')).ToLower() == "dkim-signature") 
                            return _verify_routine(NormalizedMessage, RequeryPublicRecord, ch[i]);
                };

                rv.PrimaryCode = Result.Code.PERMFAIL;
                rv.SecondaryCode = Result.ExtendedCode.NoSignature;
                return rv;
            }

            public List<Result> VerifyAllSignatures(string NormalizedMessage) { return VerifyAllSignatures(NormalizedMessage, true); }
            public List<Result> VerifyAllSignatures(string NormalizedMessage, bool RequeryPublicRecord)
            {
                List<Result> rv = new List<Result>();
                string[] ch; int i;

                ch = Canonicalization.GetCanonicalHeaders(ref NormalizedMessage, Canonicalization.Algorithm.Simple); // get intact headers

                for (i = 0; i < ch.Length; ++i) // iterate dsigs top to bottom
                {
                    if (ch[i].Substring(0, ch[i].IndexOf(':')).Trim().ToLower() == "dkim-signature") rv.Add(_verify_routine(NormalizedMessage, RequeryPublicRecord, ch[i]));
                };

                return rv;
            }
        }

        public static string ComposePublicRecord(object PublicKey)
        { return ComposePublicRecord(PublicKey, SignerPolicy.Default, SignatureAlgorithm.Unknown, null); }
        public static string ComposePublicRecord(object PublicKey, DKIM.SignerPolicy DeclaredSignerPolicy)
        { return ComposePublicRecord(PublicKey, DeclaredSignerPolicy, SignatureAlgorithm.Unknown, null); }
        public static string ComposePublicRecord(object PublicKey, DKIM.SignerPolicy DeclaredSignerPolicy, DKIM.SignatureAlgorithm DeclaredHashAlgorithms)
        { return ComposePublicRecord(PublicKey, DeclaredSignerPolicy, DeclaredHashAlgorithms, null); }
        public static string ComposePublicRecord(object PublicKey, DKIM.SignerPolicy DeclaredSignerPolicy, DKIM.SignatureAlgorithm DeclaredHashAlgorithms, string Note)
        {
            StringBuilder rv; int pbkt = -1; RSAParameters pbk1 = new RSAParameters();

            rv = new StringBuilder(512);
            try // TODO other key types
            {
                if (PublicKey.GetType() == typeof(string)) { pbk1 = Utils.Cryptography.RSA.Base64ToParams((string)PublicKey); pbkt = 0; }// try pem
                else if (PublicKey.GetType() == typeof(byte[])) { pbk1 = Utils.Cryptography.RSA.Asn1DerToParams((byte[])PublicKey); pbkt = 0; } // try der
                else if (PublicKey == null) { pbkt = -1; } // revoked key
                else throw new ArgumentException("Unrecognized public key format");
            }
            catch (Exception e) { throw e; };

            rv.Append("v=DKIM1;");

            if (pbkt < 0) { if (rv.Length > 0) rv.Append(' '); rv.Append("p=;"); } // revoked key
            else if (pbkt == 0)
            {
                if (rv.Length > 0) rv.Append(' ');
                rv.Append("k=rsa;");
                rv.Append("p=" + Utils.Cryptography.RSA.ParamsToBase64(pbk1, false, false) + ';');
                pbk1.D = null; pbk1.P = null; pbk1.Q = null; pbk1.DP = null; pbk1.DQ = null; pbk1.InverseQ = null; // clear private components if present
            }; // else other key types

            if ((DeclaredSignerPolicy & SignerPolicy.Testing) == SignerPolicy.Testing) { if (rv.Length > 0) rv.Append(' '); rv.Append("t=y;"); }
            else if ((DeclaredSignerPolicy & SignerPolicy.Strict) == SignerPolicy.Strict) { if (rv.Length > 0) rv.Append(' '); rv.Append("t=s;"); }

            if (DeclaredHashAlgorithms != SignatureAlgorithm.Unknown)
            {
                if (rv.Length > 0) rv.Append(' ');
                rv.Append("h=");
                if ((DeclaredHashAlgorithms & SignatureAlgorithm.Sha1RSA) == SignatureAlgorithm.Sha1RSA)
                {
                    rv.Append("sha1");
                };
                if ((DeclaredHashAlgorithms & SignatureAlgorithm.Sha256RSA) == SignatureAlgorithm.Sha256RSA)
                {
                    if (DeclaredHashAlgorithms != SignatureAlgorithm.Sha256RSA) rv.Append(':');
                    rv.Append("sha256");
                };
                rv.Append(';');
            };

            if (Note != null && Note.Trim().Length > 0) { if (rv.Length > 0) rv.Append(' '); rv.Append("n=" + DKIM.Encoding.ToQuotedPrintable(Note) + ';'); }; // wtf am i writing

            return rv.ToString();
        }

        public static string GetHeader(ref string NormalizedMessage, string HeaderName)
        {
            string rv = null;

            _adjust_header(ref NormalizedMessage, HeaderName, 0, ref rv, null, false, false);

            return rv;
        }

        public static void SetHeader(ref string NormalizedMessage, string HeaderName, string Value) { SetHeader(ref NormalizedMessage, HeaderName, Value, false); }
        public static void SetHeader(ref string NormalizedMessage, string HeaderName, string Value, bool Append)
        {
            string rv = null;

            _adjust_header(ref NormalizedMessage, HeaderName, 0, ref rv, Value, Append, false);
        }

        public static void DeleteHeaders(ref string NormalizedMessage, string HeaderName) // TODO naming & args
        {
            StringBuilder rv = new StringBuilder(NormalizedMessage.Length);
            string[] ln = null; string[] lt = null;
            int i, j; string hk = HeaderName.Trim().ToLower();
            _break_lines(ref NormalizedMessage, ref ln, ref lt, true, false, false);

            for (i = 0; i < ln.Length; ++i)
            {
                j = ln[i].IndexOf(':');

                if (j >= 1 && (ln[i].Substring(0, j).TrimEnd().ToLower() == hk || ln[i].Substring(0, j).TrimEnd().ToLower().StartsWith(hk)))
                {
                    ++i; while (i < ln.Length) { if (ln[i] == null || ln[i].Length == 0 || !char.IsWhiteSpace(ln[i][0])) break; ++i; }; // skip until end | other header | body

                    if (i < ln.Length) --i; // step back
                }
                else { rv.Append(ln[i]); rv.Append(lt[i]); };
            };

            NormalizedMessage = rv.ToString();
        }
    }
}