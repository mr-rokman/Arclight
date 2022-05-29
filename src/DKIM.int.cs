using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;

namespace Arclight
{
    public static partial class DKIM
    {
        public partial class Signer
        {
            protected void clear_keys()
            {
                _pvk_rsa.Modulus = null;
                _pvk_rsa.Exponent = null;
                _pvk_rsa.D = null;
                _pvk_rsa.P = null;
                _pvk_rsa.Q = null;
                _pvk_rsa.DP = null;
                _pvk_rsa.DQ = null;
                _pvk_rsa.InverseQ = null;
            }

            protected string _compose_dsig_h(ref string[] _chead)
            {
                string rv = new string('0', 0); int i, j, c = 0;

                for (i = 0; i < this.HeaderOptions.Count; ++i)
                {
                    c = 0;

                    for (j = _chead.Length - 1; j >= 0; --j) if (HeaderOptions[i].Name.ToUpper() == _chead[j].Substring(0, _chead[j].IndexOf(':')).ToUpper()) ++c; // occurence counter

                    if (c == 0)
                    {
                        if ((this.HeaderOptions[i].Traits & HeaderOption.Trait.SignEmptyValue) == HeaderOption.Trait.SignEmptyValue)
                        {
                            if (rv.Length > 0) rv += ':';
                            rv += this.HeaderOptions[i].Name.ToLower();
                        }
                        else if ((this.HeaderOptions[i].Traits & HeaderOption.Trait.OmitIfMissing) == HeaderOption.Trait.OmitIfMissing) continue; // skip
                        else throw new InvalidOperationException("Expected header missing (" + HeaderOptions[i].Name.ToLower() + ")"); // !SignEmptyValue == header must be present
                    }
                    else if (c == 1 || (c > 1 && ((this.HeaderOptions[i].Traits & HeaderOption.Trait.SignAllOccurences) != HeaderOption.Trait.SignAllOccurences)))
                    {
                        if (rv.Length > 0) rv += ':';
                        rv += this.HeaderOptions[i].Name.ToLower();
                    }
                    else
                    {
                        while (c > 0)
                        {
                            if (rv.Length > 0) rv += ':';
                            rv += this.HeaderOptions[i].Name.ToLower();

                            --c;
                        };
                    };
                };

                return rv;
            }

            protected byte[] _compute_head_hash(ref string[] _chead, string _dsig_stub, HashAlgorithm _hash)
            {
                byte[] bb; int i, j, c = 0;
                byte[] crlf = new byte[2] { (byte)'\r', (byte)'\n' };

                if (_hash == null) return null;

                _hash.Initialize(); // begin madness

                for (i = 0; i < this.HeaderOptions.Count; ++i)
                {
                    c = 0;

                    for (j = _chead.Length - 1; j >= 0; --j) if (HeaderOptions[i].Name.ToUpper() == _chead[j].Substring(0, _chead[j].IndexOf(':')).ToUpper()) ++c; // occurence counter

                    if (c == 0)
                    {
                        if ((this.HeaderOptions[i].Traits & HeaderOption.Trait.SignEmptyValue) == HeaderOption.Trait.SignEmptyValue)
                        {
                            /* <...> When
                            computing the signature, the nonexisting header field MUST be treated
                            as the null string (including the header field name, header field
                         
                            value, all punctuation, and the trailing CRLF). <...>
                            */
                        }
                        else if ((this.HeaderOptions[i].Traits & HeaderOption.Trait.OmitIfMissing) == HeaderOption.Trait.OmitIfMissing) continue;
                        else throw new Exception(); // !SignEmptyValue == header must be present
                    }
                    else if (c == 1 || (c > 1 && ((this.HeaderOptions[i].Traits & HeaderOption.Trait.SignAllOccurences) != HeaderOption.Trait.SignAllOccurences)))
                    {
                        for (j = _chead.Length - 1; j >= 0; --j) if (HeaderOptions[i].Name.ToUpper() == _chead[j].Substring(0, _chead[j].IndexOf(':')).ToUpper()) break;

                        bb = System.Text.Encoding.ASCII.GetBytes(_chead[j]);

                        _hash.TransformBlock(bb, 0, bb.Length, bb, 0);
                        _hash.TransformBlock(crlf, 0, crlf.Length, crlf, 0);
                    }
                    else
                    {
                        for (j = _chead.Length - 1; j >= 0; --j)
                        {
                            if (HeaderOptions[i].Name.ToUpper() == _chead[j].Substring(0, _chead[j].IndexOf(':')).ToUpper())
                            {
                                bb = System.Text.Encoding.ASCII.GetBytes(_chead[j]);

                                _hash.TransformBlock(bb, 0, bb.Length, bb, 0);
                                _hash.TransformBlock(crlf, 0, crlf.Length, crlf, 0);
                            };
                        };
                    };
                };

                bb = System.Text.Encoding.ASCII.GetBytes(_dsig_stub);
                _hash.TransformFinalBlock(bb, 0, bb.Length); // end madness

                return _hash.Hash;
            }

            protected string _get_header_value(ref string[] _chead, string _name)
            {
                int i, j;

                if (_chead == null || _chead.Length == 0 || _name == null || _name.Trim().Length == 0) return string.Empty;
                for (i = 0; i < _chead.Length; ++i)
                {
                    j = -1; j = _chead[i].IndexOf(':');
                    if (j >= 1) // at least 1 symbol in k
                    {
                        if (_chead[i].Substring(0, j).ToUpper() == _name.Trim().ToUpper()) return _chead[i].Substring(j + 1, _chead[i].Length - j - 1).TrimStart(); // omit possible extra wps
                    };
                };

                return string.Empty;
            }

            protected string _compose_dsig_stub(string _dsig_bh, string _dsig_h, bool _use_canon, bool _sp_suffix, DateTime _sts) // MAYBE add z=
            {
                System.Globalization.IdnMapping dm = new System.Globalization.IdnMapping(); // idna mapper

                string rv = "DKIM-Signature:"; if (true) rv += ' ';

                // version
                rv += "v=1;"; if (true) rv += ' ';

                // signature algorithm
                if (_sign_algo == SignatureAlgorithm.Sha1RSA) { rv += "a=rsa-sha1;"; if (true) rv += ' '; }
                else if (_sign_algo == SignatureAlgorithm.Sha256RSA) { rv += "a=rsa-sha256;"; if (true) rv += ' '; }

                // pbk query method
                if (_dsig_verbose) { rv += "q=dns/text;"; if (true) rv += ' '; };

                // canonicalization algorithms
                rv += "c=" + (_head_can_algo == Canonicalization.Algorithm.Simple ? "simple" : "relaxed") + '/' + (_body_can_algo == Canonicalization.Algorithm.Simple ? "simple" : "relaxed") + ';'; if (true) rv += ' ';

                // domain
                if (_domain_explicit != null) { rv += "d=" + dm.GetAscii(_domain_explicit) + ';'; if (true) rv += ' '; }
                else if (_domain_implicit != null) { rv += "d=" + dm.GetAscii(_domain_implicit) + ';'; if (true) rv += ' '; }
                else throw new InvalidOperationException("No domain name"); // fubar

                // selector
                if (_selector != null) { rv += "s=" + dm.GetAscii(_selector) + ';'; if (true) rv += ' '; }
                else throw new InvalidOperationException("No selector name"); // fubar

                // auid
                if (_auid != null) { rv += "i=" + Encoding.ToQuotedPrintable(_auid, false) + ';'; if (true) rv += ' '; };

                // headers list
                rv += "h=" + _dsig_h + ';'; if (true) rv += ' ';

                // timestamp & expiration
                rv += "t=" + Math.Floor(_sts.Subtract(_unix_zerotime).TotalSeconds).ToString() + ';'; if (true) rv += ' ';
                if (this.IsSignatureTimeLimited)
                { rv += "x=" + Math.Floor(_sts.ToUniversalTime().Add(this.SignatureValidityPeriod).Subtract(_unix_zerotime).TotalSeconds).ToString() + ';'; if (true) rv += ' '; };

                // body length
                if (this.IsBodyLengthLimited)
                { rv += "l=" + this.BodyLengthLimit.ToString() + ';'; if (true) rv += ' '; };

                // body hash
                rv += "bh=" + _dsig_bh + ';'; if (true) rv += ' ';

                // signature blob
                rv += "b="; // empty

                if (_use_canon) rv = Canonicalization.GetCanonicalHeader(rv, _head_can_algo, false);

                return rv;
            }

            protected string _sign_routine(string _msg, Option _opts, ref string _out_dsig)
            {
                HashAlgorithm hasher; AsymmetricAlgorithm cipher; AsymmetricSignatureFormatter signer;
                string[] chead;
                string cbody;
                string dsig; byte[] bh; string bhs; string h; DateTime sts;

                byte[] bb = null, bb2 = null; int i, j; bool f;

                chead = Canonicalization.GetCanonicalHeaders(ref _msg, _head_can_algo);
                cbody = Canonicalization.GetCanonicalBody(ref _msg, _body_can_algo);

                if (_sign_all_head) // butwhy.gif
                {
                    this.HeaderOptions.Clear();

                    for (i = 0; i < chead.Length; ++i)
                    {
                        this.HeaderOptions.Add(new HeaderOption(chead[i].Substring(0, chead[i].IndexOf(':')), HeaderOption.Trait.SignAllOccurences));
                    };

                    _opts = Option.Default; // avoid reconstruction at end
                }
                else if (_opts == Option.SignExistingSignatures) // tricky
                {
                    f = false;

                    for (i = 0; i < this.HeaderOptions.Count; ++i)
                    {
                        if (this.HeaderOptions[i].Name.ToLower() == "dkim-signature")
                        {
                            this.HeaderOptions[i].Traits = HeaderOption.Trait.SignAllOccurences | HeaderOption.Trait.OmitIfMissing; // ensure flags
                            f = true;
                            break;
                        };
                    };

                    if (!f) this.HeaderOptions.Add(new DKIM.Signer.HeaderOption("DKIM-Signature", HeaderOption.Trait.SignAllOccurences | HeaderOption.Trait.OmitIfMissing)); // add if missing
                }
                else if (_opts == Option.RemoveExistingSignatures)
                {
                    for (i = 0; i < this.HeaderOptions.Count; ++i)
                    {
                        if (this.HeaderOptions[i].Name.ToLower() == "dkim-signature") { this.HeaderOptions.RemoveAt(i); break; }; // remove if present
                    };
                };

                if (_domain_explicit == null)
                {
                    try // extract domain part outta "from" header
                    {
                        _domain_implicit = Regex.Match(_get_header_value(ref chead, "from"), _regex_domain).Groups[1].Value;
                    }
                    catch { throw new InvalidOperationException("Domain name is required"); };
                };

                // body hash prep
                if (_bodylen != 0)
                {
                    if ((ulong)cbody.Length < _bodylen) _bodylen = (ulong)cbody.Length; // MAYBE instead hash overflow bytes as 0x00,  RFC says nothing about this scenario
                    Encoding.GetEncodingFromHeaders(chead).GetBytes(cbody.Substring(0, (int)_bodylen));
                }
                else bb = Encoding.GetEncodingFromHeaders(chead).GetBytes(cbody);

                for (i = 0; i < bb.Length; ++i) { bb[i] = (byte)cbody[i]; }; // sucks MAYBE optimize

                try
                {
                    // hash/sign algo selector
                    if (_sign_algo == SignatureAlgorithm.Sha1RSA)
                    {
                        hasher = new SHA1Managed();
                        signer = new RSAPKCS1SignatureFormatter();
                        cipher = new RSACryptoServiceProvider();

                        ((RSACryptoServiceProvider)cipher).ImportParameters(_pvk_rsa);
                        signer.SetKey(cipher);
                    }
                    else if (_sign_algo == SignatureAlgorithm.Sha256RSA)
                    {
                        hasher = new SHA256Managed();
                        signer = new RSAPKCS1SignatureFormatter();
                        cipher = new RSACryptoServiceProvider();

                        ((RSACryptoServiceProvider)cipher).ImportParameters(_pvk_rsa);
                        signer.SetKey(cipher);
                    }
                    else throw new InvalidOperationException("Unknown signature algorihtm");

                    // signature timestamp
                    sts = DateTime.UtcNow;

                    // dsig parameters
                    hasher.Initialize(); bh = hasher.ComputeHash(bb); bhs = Convert.ToBase64String(bh); // body hash
                    h = _compose_dsig_h(ref chead); if (h == null || h.Length == 0) throw new InvalidOperationException("No headers were selected"); // h parameter
                    dsig = _compose_dsig_stub(bhs, h, true, false, sts);

                    _compute_head_hash(ref chead, dsig, hasher); // headers + stub hash

                    // signing
                    if (_sign_algo == SignatureAlgorithm.Sha1RSA) bb2 = signer.CreateSignature(hasher);// PKCS#1 1.5
                    else if (_sign_algo == SignatureAlgorithm.Sha256RSA) bb2 = signer.CreateSignature(hasher); // (same)
                    else throw new InvalidOperationException("Unknown signature algorihtm");
                    signer = null;

                    // final composition
                    dsig = _compose_dsig_stub(bhs, h, false, true, sts) + System.Convert.ToBase64String(bb2);

                    // if instructed, output DSIG and bail ...
                    if (_out_dsig != null) { _out_dsig = dsig; return null; };

                    // ... otherwise proceed composing rv
                    StringBuilder rv = new StringBuilder(dsig.Length + 2 + _msg.Length); // dsig + CRLF + rest of data

                    rv.Append(dsig); rv.Append("\r\n"); // computed dsig + lt ...

                    if (_opts == Option.RemoveExistingSignatures) // omit any existing dsig headers from input data ...
                    {
                        string[] ln = null; string[] lt = null;
                        _break_lines(ref _msg, ref ln, ref lt, true, false, false);

                        for (i = 0; i < ln.Length; ++i)
                        {
                            j = ln[i].IndexOf(':');

                            if (j >= 1 && ln[i].Substring(0, j).TrimEnd().ToLower() == "dkim-signature") // found dsig
                            {
                                ++i; while (i < ln.Length) { if (ln[i] == null || ln[i].Length == 0 || !char.IsWhiteSpace(ln[i][0])) break; ++i; }; // skip until end | other header | body

                                if (i < ln.Length) --i; // step back
                            }
                            else { rv.Append(ln[i]); rv.Append(lt[i]); };
                        };
                    }
                    else rv.Append(_msg); // ... or just write as is

                    return rv.ToString();
                }
                finally
                {
                    // TODO crypto cleanup if required
                }
            }
        }

        public partial class Verifier
        {
            protected void _parse_pr(string _pr, ref CipherKind _k, ref byte[] _p, ref SignerPolicy _t, ref HashKind _h, ref string _n)
            {
                string iv;
                string[] tok, tok2; int i, j; bool f;

                iv = _pr.Trim();

                tok = iv.Split(';');

                for (i = 0; i < tok.Length; ++i)
                {
                    tok[i] = tok[i].Trim();
                    if (tok[i].Length == 0) continue;

                    j = tok[i].IndexOf('=');
                    if (j < 0) continue;

                    switch (tok[i].Substring(0, j).ToLower())
                    {
                        case "v": // marker
                            if (tok[i].Substring(j + 1) != "DKIM1") throw new FormatException("Malformed public record");
                            break;
                        case "k": // pbk algo
                            if (tok[i].Substring(j + 1).ToLower() == "rsa") _k = CipherKind.RSA;
                            else _k = CipherKind.Unknown;
                            break;
                        case "p": // pbk
                            if (tok[i].Substring(j + 1).Trim().Length == 0) _p = null; // revoked key
                            else
                            {
                                try { _p = Utils.Cryptography.RSA.ParamsToAsn1Der(Utils.Cryptography.RSA.Base64ToParams(tok[i].Substring(j + 1)), false); }
                                catch { throw new FormatException("Unrecognized public key data"); };
                            };
                            break;
                        case "h": // hash algos
                            if (tok[i].Substring(j + 1).Trim().Length == 0) break; // no data defined

                            tok2 = tok[i].Substring(j + 1).Split(':');
                            for (j = 0; j < tok2.Length; ++j)
                            {
                                switch (tok2[j].Trim().ToLower())
                                {
                                    case "sha1":
                                        _h = (_h | HashKind.SHA1);
                                        break;
                                    case "sha256":
                                        _h = (_h | HashKind.SHA256);
                                        break;
                                    default: continue;
                                };
                            };
                            break;
                        case "t": // flags & policies
                            if (tok[i].Substring(j + 1).Trim().Length == 0) break; // no data defined

                            tok2 = tok[i].Substring(j + 1).Split(':');
                            for (j = 0; j < tok2.Length; ++j)
                            {
                                switch (tok2[j].Trim().ToLower())
                                {
                                    case "y":
                                        _t = SignerPolicy.Testing;
                                        break;
                                    case "s":
                                        _t = SignerPolicy.Strict;
                                        break;
                                    default: continue;
                                };
                            };
                            break;
                        case "s": // service types
                            if (tok[i].Substring(j + 1).Trim().Length == 0) break; // no data defined

                            tok2 = tok[i].Substring(j + 1).Split(':'); f = false; // if defined, check for either "*" or "email"; otherwise pr is unacceptable
                            for (j = 0; j < tok2.Length; ++j)
                            {
                                switch (tok2[i].Trim().ToLower())
                                {
                                    case "email":
                                    case "*":
                                        f = true;
                                        break;
                                    default: continue;
                                };
                            };

                            if (!f) throw new InvalidDataException("Declared service usage is unacceptable");
                            break;
                        case "n:": // note
                            if (tok[i].Substring(j + 1).Trim().Length == 0)
                            { _n = string.Empty; break; } // no data defined
                            else _n = Encoding.FromDKIMQuotedPrintable(tok[i].Substring(j + 1).Trim());
                            break;
                        default: continue;
                    };
                };
            }

            protected void _parse_dsig(string _dsig, ref SignatureAlgorithm _a, ref string _d, ref string _s, ref DateTime _t, ref DateTime _x, ref string _i, ref Canonicalization.Algorithm _ch,
                    ref Canonicalization.Algorithm _cb, ref ulong _l, ref List<HeaderOption> _h, ref byte[] _bh, ref byte[] _b) // no q= , z=
            {
                System.Globalization.IdnMapping idna = new System.Globalization.IdnMapping();
                string iv = null; int i, j;
                string[] tok, tok2;
                ulong nb1;

                _adjust_header(ref _dsig, "dkim-signature", 0, ref iv, null, false, true);

                i = iv.IndexOf(':'); if (i < 0) throw new Exception();

                if (iv.Substring(0, i).Trim().ToLower() != "dkim-signature") throw new Exception();

                // iv = _dsig.Substring(i + 1).Trim(); if (iv.Length < 4 || iv.Substring(0, 4).Trim().ToLower() != "v=1;") throw new ArgumentOutOfRangeException();

                // init defaults
                _a = SignatureAlgorithm.Unknown;
                _ch = Canonicalization.Algorithm.Simple;
                _cb = Canonicalization.Algorithm.Simple;
                _t = DateTime.MinValue; _x = DateTime.MaxValue;
                _l = 0;
                _i = string.Empty;

                tok = iv.Split(';');
                for (i = 0; i < tok.Length; ++i)
                {
                    tok[i] = tok[i].Trim();

                    if (tok[i].Length == 0) continue;

                    j = tok[i].IndexOf('='); if (j < 0) throw new Exception();

                    switch (tok[i].Substring(0, j).ToLower())
                    {
                        case "v":
                            if (tok[i].Substring(j + 1).Trim().ToLower() != "1") throw new ArgumentOutOfRangeException();
                            break;
                        case "a":
                            if (tok[i].Substring(j + 1).Trim().ToLower() == "rsa-sha1") _a = SignatureAlgorithm.Sha1RSA;
                            else if (tok[i].Substring(j + 1).Trim().ToLower() == "rsa-sha256") _a = SignatureAlgorithm.Sha256RSA;
                            else throw new NotImplementedException("a");
                            break;
                        case "c":
                            tok2 = tok[i].Substring(j + 1).Trim().ToLower().Split('/');
                            if (tok2.Length != 2) throw new Exception();

                            if (tok2[0].Trim().ToLower() == "simple") _ch = Canonicalization.Algorithm.Simple;
                            else if (tok2[0].Trim().ToLower() == "relaxed") _ch = Canonicalization.Algorithm.Relaxed;
                            else throw new NotImplementedException("c");

                            if (tok2[1].Trim().ToLower() == "simple") _cb = Canonicalization.Algorithm.Simple;
                            else if (tok2[1].Trim().ToLower() == "relaxed") _cb = Canonicalization.Algorithm.Relaxed;
                            else throw new NotImplementedException("c");
                            break;
                        case "s":
                            _s = idna.GetUnicode(tok[i].Substring(j + 1).Trim()); if (_s == null || _s.Length == 0) throw new MissingFieldException("s");
                            break;
                        case "d":
                            _d = idna.GetUnicode(tok[i].Substring(j + 1).Trim()); if (_d == null || _d.Length == 0) throw new MissingFieldException("d");
                            break;
                        case "t":
                            nb1 = ulong.Parse(tok[i].Substring(j + 1).Trim());
                            _t = (_unix_zerotime).AddSeconds((double)nb1);
                            break;
                        case "x":
                            nb1 = ulong.Parse(tok[i].Substring(j + 1).Trim());
                            _x = (_unix_zerotime).AddSeconds((double)nb1);
                            break;
                        case "l":
                            _l = ulong.Parse(tok[i].Substring(j + 1).Trim());
                            break;
                        case "i":
                            _i = Encoding.FromDKIMQuotedPrintable(tok[i].Substring(j + 1));
                            break;
                        case "bh":
                            if (tok[i].Substring(j + 1).Length == 0) throw new MissingFieldException("bh");
                            _bh = System.Convert.FromBase64String(tok[i].Substring(j + 1).Trim());
                            break;
                        case "b":
                            if (tok[i].Substring(j + 1).Length == 0) throw new MissingFieldException("b");
                            _b = System.Convert.FromBase64String(tok[i].Substring(j + 1).Trim());
                            break;
                        case "h":
                            if (tok[i].Substring(j + 1).Length == 0) throw new MissingFieldException("h");
                            tok2 = tok[i].Substring(j + 1).Trim().ToLower().Split(':');

                            Dictionary<string, ushort> dict = new Dictionary<string, ushort>(tok2.Length);

                            for (j = 0; j < tok2.Length; ++j)
                            {
                                if (tok2[j].Trim().Length == 0) throw new Exception();

                                if (_h == null) _h = new List<HeaderOption>();

                                if (dict.ContainsKey(tok2[j].Trim().ToLower()))
                                {
                                    ++dict[tok2[j].Trim().ToLower()]; // increase rord

                                    _h.Add(new HeaderOption(tok2[j].Trim().ToLower(), dict[tok2[j].Trim().ToLower()]));
                                }
                                else
                                {
                                    dict.Add(tok2[j].Trim().ToLower(), 1);

                                    _h.Add(new HeaderOption(tok2[j].Trim().ToLower(), 1));
                                };
                            };

                            break;
                        default: continue;
                    };
                };

                if (_a == SignatureAlgorithm.Unknown) throw new MissingFieldException("a");
                if (_s == null || _s.Length == 0) throw new MissingFieldException("s");
                if (_d == null || _d.Length == 0) throw new MissingFieldException("d");
                if (_bh == null || _bh.Length == 0) throw new MissingFieldException("bh");
                if (_b == null || _b.Length == 0) throw new MissingFieldException("b");
                if (_h == null || _h.Count == 0) throw new MissingFieldException("h");

                else return;
            }
            
            protected string _dsig_to_stub(string _dsig, Canonicalization.Algorithm _can_algo)
            {
                StringBuilder rv;
                string iv; int i, j; bool f;
                string[] tok;

                i = _dsig.IndexOf(':'); if (i < 0) throw new FormatException();
                iv = _dsig.Substring(0, i).Trim();

                if (iv.ToLower() != "dkim-signature") throw new FormatException();

                rv = new StringBuilder(_dsig.Length);
                rv.Append(iv); rv.Append(':'); // preserve case

                iv = _dsig.Substring(i + 1).Trim(); // if (iv.Length < 4 || iv.Substring(0, 4).Trim().ToLower() != "v=1;") throw new Exception();

                f = iv[iv.Length - 1] == ';' ? true : false; // ender flag

                tok = iv.Split(';');
                for (i = 0; i < tok.Length; ++i)
                {
                    j = tok[i].IndexOf('=');

                    if (j < 0) // bullshit, but we let it slide for now
                    {
                        rv.Append(tok[i]);
                    }
                    else if(tok[i].Substring(0, j).Trim().ToLower() == "b") // omit v
                    {
                        rv.Append(tok[i].Substring(0, j + 1)); // including "=" sign
                    }
                    else // pass-through
                    {
                        rv.Append(tok[i]); // rv.Append(tok[i].Substring(0, j).Trim()); rv.Append('='); rv.Append(tok[i].Substring(j + 1).Trim());
                    };

                    if (i < tok.Length - 1 || (i == tok.Length - 1 && f)) rv.Append(';'); // append separator between tokens + ender if present
                };

                return Canonicalization.GetCanonicalHeader(rv.ToString(), _can_algo, false);
            }

            protected byte[] _compute_head_hash(ref string[] _chead, List<HeaderOption> _dsig_h, string _dsig_stub, HashAlgorithm _hash)
            {
                byte[] bb; int i, j, c;
                byte[] crlf = new byte[2] { (byte)'\r', (byte)'\n' };

                if (_hash == null) return null;

                _hash.Initialize(); // begin madness

                for (i = 0; i < _dsig_h.Count; ++i)
                {
                    c = _dsig_h[i].ReverseOrdinal; // target rord

                    for (j = _chead.Length - 1; j >= 0; --j)
                    {
                        if (_dsig_h[i].Name.ToUpper() == _chead[j].Substring(0, _chead[j].IndexOf(':')).ToUpper())
                        {
                            if (c == 1) // target found
                            {
                                bb = System.Text.Encoding.ASCII.GetBytes(_chead[j]);

                                _hash.TransformBlock(bb, 0, bb.Length, bb, 0);
                                _hash.TransformBlock(crlf, 0, crlf.Length, crlf, 0);

                                break;
                            }
                            else --c;
                        };
                    };
                };

                bb = System.Text.Encoding.ASCII.GetBytes(_dsig_stub);
                _hash.TransformFinalBlock(bb, 0, bb.Length); // end madness

                return _hash.Hash;
            }

            protected Result _verify_routine(string _msg, bool _rq_pr, string _dsig)
            {
                Result rv = new Result(); HashAlgorithm hasher; AsymmetricAlgorithm cipher; AsymmetricSignatureDeformatter verifier;
                string[] chead; string cbody;
                string pr = null;
                byte[] bb; bool f; DateTime vts;

                CipherKind pr_k = CipherKind.Unknown;
                byte[] pr_p = null;
                SignerPolicy pr_t = SignerPolicy.Default;
                HashKind pr_h = HashKind.Unknown;
                string pr_n = string.Empty;

                SignatureAlgorithm dsig_a = SignatureAlgorithm.Unknown;
                string dsig_d = null, dsig_s = null, dsig_i = null;
                DateTime dsig_t = DateTime.MinValue, dsig_x = DateTime.MaxValue;
                Canonicalization.Algorithm dsig_ch = Canonicalization.Algorithm.Simple, dsig_cb = Canonicalization.Algorithm.Simple;
                ulong dsig_l = 0;
                List<HeaderOption> dsig_h = null;
                byte[] dsig_bh = null, dsig_b = null, comp_bh = null;

                // verification timestamp
                vts = DateTime.UtcNow;

                if (_dsig == null || _dsig.Length == 0)
                {
                    rv.PrimaryCode = Result.Code.PERMFAIL;
                    rv.SecondaryCode = Result.ExtendedCode.NoSignature;
                    return rv;
                };

                // parsing and shitload of checks
                try { _parse_dsig(_dsig, ref dsig_a, ref dsig_d, ref dsig_s, ref dsig_t, ref dsig_x, ref dsig_i, ref dsig_ch, ref dsig_cb, ref dsig_l, ref dsig_h, ref dsig_bh, ref dsig_b); }
                catch (ArgumentOutOfRangeException)
                {
                    rv.PrimaryCode = Result.Code.PERMFAIL;
                    rv.SecondaryCode = Result.ExtendedCode.MalformedSignature;
                    rv.Information = "incompatible version";
                    rv.ElapsedMillis = (ulong)DateTime.UtcNow.Subtract(vts).TotalMilliseconds;
                    return rv;
                }
                catch (MissingFieldException e1)
                {
                    rv.PrimaryCode = Result.Code.PERMFAIL;
                    rv.SecondaryCode = Result.ExtendedCode.MalformedSignature;
                    rv.Information = "syntax error in signature (" + e1.Message + "-tag)";
                    rv.ElapsedMillis = (ulong)DateTime.UtcNow.Subtract(vts).TotalMilliseconds;
                    return rv;
                }
                catch (Exception)
                {
                    rv.PrimaryCode = Result.Code.PERMFAIL;
                    rv.SecondaryCode = Result.ExtendedCode.MalformedSignature;
                    rv.Information = "syntax error in signature";
                    rv.ElapsedMillis = (ulong)DateTime.UtcNow.Subtract(vts).TotalMilliseconds;
                    return rv;
                };

                if (_rq_pr)
                {
                    try { pr = new List<string>(Utils.SystemDns.GetTxtRecords(dsig_s + "._domainkey." + dsig_d))[0]; } // TODO support multiple records in case the SUDDENLY appear
                    catch // TODO distinguish between transient / permanent fail
                    {
                        rv.PrimaryCode = Result.Code.TEMPFAIL;
                        rv.SecondaryCode = Result.ExtendedCode.NoPublicRecord;
                        rv.ElapsedMillis = (ulong)DateTime.UtcNow.Subtract(vts).TotalMilliseconds;
                        return rv;
                    };

                    try { _parse_pr(pr, ref pr_k, ref pr_p, ref pr_t, ref pr_h, ref pr_n); }
                    catch (InvalidDataException)
                    {
                        rv.PrimaryCode = Result.Code.PERMFAIL;
                        rv.SecondaryCode = Result.ExtendedCode.UnacceptablePublicRecord;
                        rv.Information = "no acceptable service found in public record (s-tag)";
                        rv.ElapsedMillis = (ulong)DateTime.UtcNow.Subtract(vts).TotalMilliseconds;
                        return rv;
                    }
                    catch (Exception)
                    {
                        rv.PrimaryCode = Result.Code.PERMFAIL;
                        rv.SecondaryCode = Result.ExtendedCode.MalformedPublicRecord;
                        rv.Information = "syntax error in public record";
                        rv.ElapsedMillis = (ulong)DateTime.UtcNow.Subtract(vts).TotalMilliseconds;
                        return rv;
                    };
                }
                else
                {
                    pr_k = this._pbk_kind;
                    pr_p = this.PublicKeyDER;
                    pr_t = _signpol;
                    pr_h = _hash_algo;

                    if (pr_p == null || pr_p.Length == 0)
                    {
                        rv.PrimaryCode = Result.Code.PERMFAIL;
                        rv.SecondaryCode = Result.ExtendedCode.RevokedKey;
                        rv.Information = "key revoked";
                        rv.ElapsedMillis = (ulong)DateTime.UtcNow.Subtract(vts).TotalMilliseconds;
                        return rv;
                    };
                };

                // hash algorithm check
                if ((pr_h == HashKind.SHA1 && dsig_a != SignatureAlgorithm.Sha1RSA)
                        || (pr_h == HashKind.SHA256 && dsig_a != SignatureAlgorithm.Sha256RSA))
                {
                    rv.PrimaryCode = Result.Code.PERMFAIL;
                    rv.SecondaryCode = Result.ExtendedCode.HashAlgorithmMismatch;
                    rv.Information = "inappropriate hash algorithm";
                    rv.ElapsedMillis = (ulong)DateTime.UtcNow.Subtract(vts).TotalMilliseconds;
                    return rv;
                };

                // timestamp clamp check
                if (dsig_t != DateTime.MinValue || dsig_x != DateTime.MaxValue)
                {
                    if (dsig_t > vts) // wat
                    {
                        rv.PrimaryCode = Result.Code.PERMFAIL;
                        rv.SecondaryCode = Result.ExtendedCode.TimestampInFuture;
                        rv.Information = "signature timestamp in future (by " + Math.Floor(dsig_t.Subtract(vts).TotalSeconds).ToString() + " s)";
                        rv.ElapsedMillis = (ulong)DateTime.UtcNow.Subtract(vts).TotalMilliseconds;
                        return rv;
                    };

                    if (dsig_x < vts)
                    {
                        rv.PrimaryCode = Result.Code.PERMFAIL;
                        rv.SecondaryCode = Result.ExtendedCode.SignatureExpired;
                        rv.Information = "signature expired (" + Math.Floor(vts.Subtract(dsig_x).TotalSeconds).ToString() + " s ago)";
                        rv.ElapsedMillis = (ulong)DateTime.UtcNow.Subtract(vts).TotalMilliseconds;
                        return rv;
                    };
                };

                // policy check
                if (pr_t == SignerPolicy.Strict && dsig_i != null && dsig_i.Length > 0)
                {
                    try // <...> Verifiers MUST confirm that the domain specified in the "d=" tag is the same as or a parent domain of the domain part of the "i=" tag <...>
                    {
                        if ((Regex.Match(dsig_i, _regex_domain).Groups[1].Value.Trim().ToLower()
                                != dsig_d.Trim().ToLower())
                                || !dsig_d.Contains(Regex.Match(dsig_i, _regex_domain).Groups[1].Value.Trim().ToLower()))

                        throw new Exception();
                    }
                    catch
                    {
                        rv.PrimaryCode = Result.Code.PERMFAIL;
                        rv.SecondaryCode = Result.ExtendedCode.PolicyViolation;
                        rv.Information = "domain mismatch";
                        rv.ElapsedMillis = (ulong)DateTime.UtcNow.Subtract(vts).TotalMilliseconds;
                        return rv;
                    };
                };

                chead = Canonicalization.GetCanonicalHeaders(ref _msg, dsig_ch);
                cbody = Canonicalization.GetCanonicalBody(ref _msg, dsig_cb);

                // body hash prep
                if (dsig_l != 0)
                {
                    if ((ulong)cbody.Length < dsig_l)
                    {
                        rv.PrimaryCode = Result.Code.PERMFAIL;
                        rv.SecondaryCode = Result.ExtendedCode.BodyTampered;
                        rv.Information = "body length less than l-tag";
                        rv.ElapsedMillis = (ulong)DateTime.UtcNow.Subtract(vts).TotalMilliseconds;
                        return rv;
                    }
                    bb = Encoding.GetEncodingFromHeaders(chead).GetBytes(cbody.Substring(0, (int)dsig_l)); // dunno
                }
                else bb = Encoding.GetEncodingFromHeaders(chead).GetBytes(cbody);

                try
                {
                    // hash/sign algo selector
                    if (dsig_a == SignatureAlgorithm.Sha1RSA)
                    {
                        hasher = new SHA1Managed();
                        verifier = new RSAPKCS1SignatureDeformatter();
                        cipher = new RSACryptoServiceProvider();

                        ((RSACryptoServiceProvider)cipher).ImportParameters(Utils.Cryptography.RSA.Asn1DerToParams(pr_p));
                        verifier.SetKey(cipher);
                    }
                    else if (dsig_a == SignatureAlgorithm.Sha256RSA)
                    {
                        hasher = new SHA256Managed();
                        verifier = new RSAPKCS1SignatureDeformatter();
                        cipher = new RSACryptoServiceProvider();

                        ((RSACryptoServiceProvider)cipher).ImportParameters(Utils.Cryptography.RSA.Asn1DerToParams(pr_p));
                        verifier.SetKey(cipher);
                    }
                    else throw new InvalidOperationException("Unknown signature algorihtm");

                    // dsig parameters
                    hasher.Initialize(); comp_bh = hasher.ComputeHash(bb); // body hash
                    if (!_is_equal(ref dsig_bh, ref comp_bh))
                    {
                        rv.PrimaryCode = Result.Code.PERMFAIL;
                        rv.SecondaryCode = Result.ExtendedCode.BodyTampered;
                        rv.Information = "body hash did not verify";
                        rv.ElapsedMillis = (ulong)DateTime.UtcNow.Subtract(vts).TotalMilliseconds;
                        return rv;
                    };

                    _compute_head_hash(ref chead, dsig_h, _dsig_to_stub(_dsig, dsig_ch), hasher); // headers + stub hash

                    // signature check
                    if (dsig_a == SignatureAlgorithm.Sha1RSA) f = verifier.VerifySignature(hasher, dsig_b);// PKCS#1 1.5
                    else if (dsig_a == SignatureAlgorithm.Sha256RSA) f = verifier.VerifySignature(hasher, dsig_b); // (same)
                    else throw new InvalidOperationException("Unknown signature algorihtm");
                    verifier = null;

                    if (!f)
                    {
                        rv.PrimaryCode = Result.Code.PERMFAIL;
                        rv.SecondaryCode = Result.ExtendedCode.MessageTampered;
                        rv.Information = "signature did not verify";
                        rv.ElapsedMillis = (ulong)DateTime.UtcNow.Subtract(vts).TotalMilliseconds;
                        return rv;
                    };

                    // all things check out
                    rv.PrimaryCode = Result.Code.SUCCESS;
                    rv.SecondaryCode = Result.ExtendedCode.None;
                    rv.Information = string.Empty;
                    rv.ElapsedMillis = (ulong)DateTime.UtcNow.Subtract(vts).TotalMilliseconds;
                    return rv;
                }
                finally
                {
                    // TODO crypto cleanup if required
                }
            }
        }

        // input -> line[] + line_terminator[]
        private static void _break_lines(ref string _input, ref string[] _ln, ref string[] _lt, bool _keep_empty_ln, bool _eof_lt, bool _implicit_lt)
        {
            int i;
            int li, c1, c2;

            if (_input == null || _input.Length == 0) // erase rv if no input
            {
                if (_ln != null && _ln.Length > 0) _ln = null;
                if (_lt != null && _lt.Length > 0) _lt = null;

                return;
            };

            li = 0; c1 = 0; c2 = 0;

            for (i = 0; i < _input.Length; ++i)
            {
                if (_input[i] == '\r') // cr | crlf
                {
                    if (i < _input.Length - 1 && _input[i + 1] == '\n') { c2 = 2; ++i; } // crlf
                    else c2 = 1; // cr
                }
                else if (_input[i] == '\n') c2 = 1; // lf
                else ++c1; // line char

                if (c2 > 0)
                {
                    if (c1 == 0 && !_keep_empty_ln) { c1 = c2 = 0; continue; }; // skip empty line if instructed

                    // adjust rv size if needed
                    if (_ln == null || _ln.Length < li + 1) { Array.Resize<string>(ref _ln, (_ln == null || _ln.Length == 0 ? (int)((double)_input.Length / 64) + 1 : _ln.Length + 100)); Array.Resize<string>(ref _lt, _ln.Length); };

                    _ln[li] = (c1 > 0 ? _input.Substring(i - c2 - c1 + 1, c1) : string.Empty); // extract line ...
                    if (!_implicit_lt) _lt[li] = _input.Substring(i - c2 + 1, c2); // ... and either real lt ...
                    else _lt[li] = "\r\n"; // .. or implicit one

                    ++li; c1 = c2 = 0;
                }
                else if (i == _input.Length - 1) // last char
                {
                    // adjust rv size if needed
                    if (_ln == null || _ln.Length < li + 1) { Array.Resize<string>(ref _ln, (_ln == null || _ln.Length == 0 ? (int)((double)_input.Length / 64) + 1 : _ln.Length + 100)); Array.Resize<string>(ref _lt, _ln.Length); };

                    _ln[li] = _input.Substring(i - c1 + 1, c1);
                    _lt[li] = _eof_lt ? "\r\n" : string.Empty; // crlf if required

                    ++li;
                };
            };

            if (li != _ln.Length) { Array.Resize<string>(ref _ln, (int)li); Array.Resize<string>(ref _lt, (int)li); };
        }

        private static DateTime _unix_zerotime = new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc);

        private static string _regex_domain = "@([^@ \\t\\r\\n\\<\\>\\!\\#\\$\\%\\^\\&\\*\\(\\)]+(?:\\.[^@ \\t\\r\\n\\<\\>\\!\\#\\$\\%\\^\\&\\*\\(\\)]|)+)"; // lol

        private static bool _is_equal(ref byte[] _a, ref byte[] _b)
        {
            if (_a == null || _b == null || _a.Length != _b.Length) return false;
            if (_a == null && _b == null) return true;

            for (ulong i = 0; i < (ulong)_a.Length; ++i) if (_a[i] != _b[i]) return false;

            return true;
        }

        private static void _adjust_header(ref string _msg, string _k, int _skips, ref string _v_out, string _v_in, bool _v_append, bool _prepend_k)
        {
            string[] ln = null, lt = null; int li = 0, li_max = -1;
            int nb1; string sb1 = null, sb2 = null; bool f = false;
            int cut1 = -1, cut2 = -1;

            if (_msg == null || _msg.Length == 0) return;

            _break_lines(ref _msg, ref ln, ref lt, true, true, true);
            if (ln == null || lt == null) return;

            // where are them headers??
            for (li = 0; li < ln.Length; ++li)
            {
                if (ln[li] == null || ln[li].Length == 0) { li_max = li - 1; break; }; // there they are
            };

            if (li_max == -1 && li > 0) li_max = ln.Length - 1; // tricky - assume input is only headers

            for (li = 0; li <= li_max; ++li)
            {
                if ((!char.IsWhiteSpace(ln[li][0]) && sb1 != null && sb1.Length > 0) || li == li_max) // new header after continuation | last line
                {
                    if (li == li_max && char.IsWhiteSpace(ln[li][0])) sb1 += ln[li].TrimStart(); // append last continuation
                    else if (li == li_max && !char.IsWhiteSpace(ln[li][0]))
                    {
                        if (sb1 == null || sb1.Length == 0) { sb1 = ln[li]; cut1 = li; } // last header
                        else f = true; // second to last header (set rewind flag)
                    };

                    nb1 = sb1.IndexOf(':'); if (nb1 < 1) throw new ArgumentException("Malformed header data");
                    if (sb1.Substring(0, nb1).Trim().ToLower() == _k.Trim().ToLower()) // found key
                    {
                        if (_skips == 0) // nth of key
                        {
                            cut2 = li;

                            if (_v_in != null) // set value
                            {
                                if (_v_append) sb2 = sb1 + _v_in; // separator at caller's discretion
                                else sb2 = sb1.Substring(0, nb1).Trim() + ": " + _v_in; // replace value
                            }
                            else // get value & return
                            {
                                if (!_prepend_k) _v_out = sb1.Substring(nb1 + 1).TrimStart();
                                else _v_out = sb1;
                                
                                return;
                            };

                            break;
                        }
                        else --_skips;
                    };

                    sb1 = null;
                    if (li < li_max || f) --li; f = false; // step back (& clear rewind flag)

                    if (cut1 >= 0 && cut2 >= 0) break;
                    else cut1 = cut2 = -1;
                }
                else if (char.IsWhiteSpace(ln[li][0]) && sb1 == null && sb1.Length == 0) throw new ArgumentException("Malformed header data"); // some bullshit
                else if (char.IsWhiteSpace(ln[li][0]) && sb1 != null && sb1.Length > 0) // folded line continuation
                {
                    sb1 += ln[li].TrimStart();
                }
                else // begin new header
                {
                    sb1 = ln[li]; cut1 = li;
                };
            };

            if (_v_in == null) { _v_out = null; return; }; // no value found

            StringBuilder rv = new StringBuilder(_msg.Length);

            if (_skips > 0 || cut1 < 0 || cut2 < 0) // nth key was not found - add new
            {
                for (li = 0; li <= li_max; ++li) { rv.Append(ln[li]); rv.Append(lt[li]); }; // all headers ...
                rv.Append(_k.Trim()); rv.Append(": "); rv.Append(_v_in); rv.Append('\r'); rv.Append('\n'); // ... new one ...

                for (li = li_max + 1; li < ln.Length; ++li) { rv.Append(ln[li]); rv.Append(lt[li]); }; // ... and the rest of message
            }
            else
            {
                for (li = 0; li < cut1; ++li) { rv.Append(ln[li]); rv.Append(lt[li]); }; // all data prior target segment ...
                rv.Append(sb2); rv.Append('\r'); rv.Append('\n'); // ... modified segment ...
                for (li = cut2 + 1; li < ln.Length; ++li) { rv.Append(ln[li]); rv.Append(lt[li]); }; // ... and the rest of message
            };

            _msg = rv.ToString();
        }

        private static void _compact_wsp(ref string _str, bool _use_sp)
        {
            int i, j = 0;

            for (i = 0; i < _str.Length; ++i)
            {
                if (char.IsWhiteSpace(_str[i]) && i < _str.Length) ++j; // wsp counter
                else if (i == _str.Length)
                {
                    if (char.IsWhiteSpace(_str[i])) ++j; // wsp counter

                    if (_use_sp) _str = _str.Substring(0, i - j) + ' '; // prev chars (+sp)
                    else _str = _str.Substring(0, i - j + 1); // prev chars (+first wsp)
                }
                else
                {
                    if (j > 1)
                    {
                        if (_use_sp) _str = _str.Substring(0, i - j) + ' ' + _str.Substring(i, _str.Length - i); // prev chars (+sp) + rest of line
                        else _str = _str.Substring(0, i - j + 1) + _str.Substring(i, _str.Length - i); // prev chars (+first wsp) + rest of line

                        j = 0;
                    }
                    else if (j == 1) // single wsp
                    {
                        if (_use_sp && _str[i - 1] != ' ') _str = _str.Substring(0, i - j) + ' ' + _str.Substring(i, _str.Length - i); // replace with sp

                        j = 0;
                    };
                };
            };
        }
    }
}