using System;
using Microsoft.Exchange.Data.Transport;
using Microsoft.Exchange.Data.Transport.Routing;
using System.Xml;
using System.IO;
using System.Diagnostics;
using System.Text;

namespace Arclight
{

    public sealed class OutboundAgentFactory : RoutingAgentFactory
    {
        public override RoutingAgent CreateAgent(SmtpServer server)
        {
            return new OutboundAgent();
        }
    }

    public sealed class OutboundAgent : RoutingAgent
    {
        private string[] _dom_key;
        private int[] _dom_ord;
        private DKIM.Signer[] _dom_signer;

        private bool _debug = false;
        private bool _log = false;
        private byte _log_type = 0;
        private object _log_obj;

        private bool _fail_deadly;

        public OutboundAgent()
        {
            DateTime ts0, ts1;

            ts0 = DateTime.Now;

            _load_cfg();

            ts1 = DateTime.Now;

            if (_dom_key != null && _dom_key.Length > 0) // at least one valid section loaded
            {
                // configuration validated - register handler
                this.OnCategorizedMessage += new CategorizedMessageEventHandler(OnCategorizedMessageHandler);

                _log_post("Initialization completed in " + ts1.Subtract(ts0).TotalMilliseconds.ToString() + " ms", true, false, false);
            }
            else
            {
                _log_post("No valid sections was loaded", true, false, false);

                return; // no valid configuration - agent going inert
            };
        }

        public void OnCategorizedMessageHandler(CategorizedMessageEventSource source, QueuedMessageEventArgs e)
        {
            try
            {
                string sb1; int nb;
                byte[] bb1;

                if (e.MailItem.Message.TnefPart != null) // tnefs or system msgs are ignored
                {
                    _log_post("Inbound message [MsgID " + e.MailItem.Message.MessageId + "] is of TNEF format and was ignored", true, false, false);
                    return;
                }
                else if (e.MailItem.Message.IsSystemMessage)
                {
                    _log_post("Inbound message [MsgID " + e.MailItem.Message.MessageId + "] is system message and was ignored", true, false, false);
                    return;
                };

                sb1 = e.MailItem.FromAddress.DomainPart.ToLower();

                nb = Array.BinarySearch<string>(_dom_key, sb1);

                if (nb < 0)
                {
                    _log_post("Outbound message [MsgID " + e.MailItem.Message.MessageId + "] ignored - unconfigured domain [" + sb1 + "]", true, false, false);

                    return;
                };

                _log_post("Outbound message [MsgID " + e.MailItem.Message.MessageId + "] being sent from [" + sb1 + "]", true, false, false);

                Stream rmsg; string msg; System.Text.Encoding enc = null;

                /*
                // mumbo-jumbo for botched encodings
                using (MemoryStream ms = new MemoryStream())
                {
                    // extract headers
                    ms.Seek(0, SeekOrigin.Begin);
                    e.MailItem.Message.RootPart.Headers.WriteTo(ms, new Microsoft.Exchange.Data.Mime.EncodingOptions("us-ascii", "en-US", Microsoft.Exchange.Data.Mime.EncodingFlags.None));

                    // extract body
                    rmsg = e.MailItem.Message.MimeDocument.RootPart.GetRawContentReadStream();
                    bb2 = new byte[rmsg.Length]; rmsg.Read(bb2, 0, bb2.Length);

                    bb1 = new byte[ms.Length + 2 + bb2.Length]; // headers + boundary + body
                    ms.Seek(0, SeekOrigin.Begin); ms.Read(bb1, 0, (int)ms.Length);
                    bb1[ms.Length] = (byte)'\r'; bb1[ms.Length + 1] = (byte)'\n';
                    Array.Copy(bb2, 0, bb1, ms.Length + 2, bb2.Length);

                    // reassemble message
                    msg = DKIM.Encoding.DecodeMessage(bb1, ref enc);
                    if (msg == null || msg.Length == 0) _log_post("Empoty!", true, false, false); else _log_post(msg, true, false, false);
                };
                */

                rmsg = e.MailItem.GetMimeReadStream();
                bb1 = new byte[rmsg.Length];
                rmsg.Read(bb1, 0, bb1.Length);
                msg = DKIM.Encoding.DecodeMessage(bb1, ref enc);

                // thanks to exchange being devil incarnate we have to unfuck message first
                string msg2 = msg, dsig;
                DKIM.DeleteHeaders(ref msg2, "x-ms-exchange-");

                try { dsig = _dom_signer[_dom_ord[nb]].ComputeSignature(msg2, DKIM.Signer.Option.Default); }
                catch (Exception e1)
                {
                    if (_fail_deadly)
                    {
                        _log_post("EXCEPTION while signing [MsgID " + e.MailItem.Message.MessageId + "] - " + e1.ToString() + " : \"" +
                                e1.Message + "\"", false, false, true);

                        _log_post("Rejecting message [MsgID " + e.MailItem.Message.MessageId + "] as mandated by policy", false, false, true);

                        source.Delete(); // TODO more elaborate way!

                        return;
                    }
                    else throw;
                };

                _log_post("Outbound message [MsgID " + e.MailItem.Message.MessageId + ") successfully signed", true, false, false); // TODO log sig params
                _log_post("Self-test on [MsgID " + e.MailItem.Message.MessageId + ") - " + (new DKIM.Verifier(_dom_signer[_dom_ord[nb]].PublicRecord)).VerifyMessage(msg, false).PrimaryCode.ToString(), true, false, false); // TODO log sig params

                _log_post("[" + msg + "]", true, false, false); // TODO log sig params

                msg = dsig + (char)'\r' + (char)'\n' + msg;

                Stream rs = e.MailItem.GetMimeWriteStream();

                bb1 = System.Text.Encoding.ASCII.GetBytes(msg); // HACK y
                rs.Write(bb1, 0, bb1.Length);
                rs.Close();

                /*
                if (wb) // for approach 2 only
                {
                    byte[] bb3;

                    bb3 = enc.GetBytes(msg); // tricky, might fuck up headers

                    try
                    {
                        e.MailItem.Message.RootPart.GetRawContentWriteStream().Write(bb3, 0, bb3.Length);
                    }
                    catch (Exception e1)
                    {
                        _log_post("Unable to write-back stream due to [" + e1.ToString() + ": \"" + e1.Message + "\"]", false, false, true);
                    };
                };
                */
            }
            catch (Exception e2)
            {
                _log_post("EXCEPTION " + e2.ToString() + ": \"" + e2.Message + "\"]", false, false, true);
            };
        }

        private bool _load_cfg()
        {
            string sb1;

            try
            {
                XmlDocument cfg = AgentBase.Configuration;

                foreach (XmlNode n0 in cfg.ChildNodes) // root element
                {
                    foreach (XmlNode n1 in n0.ChildNodes)
                    {
                        if (n1.NodeType == XmlNodeType.Element && n1.Name.ToLower() == "arclight.signer")
                        {
                            if (n1.Attributes.Count > 0)
                            {
                                foreach (XmlAttribute n1a in n1.Attributes)
                                {
                                    if (n1a.Name.ToLower() == "enabled" && !AgentBase._is_true(n1a)) return false; // must be enabled
                                    else if (n1a.Name.ToLower() == "debug" && AgentBase._is_true(n1a)) _debug = true;
                                    else if (n1a.Name.ToLower() == "mandatory" && AgentBase._is_true(n1a)) _fail_deadly = true;
                                    else if (n1a.Name.ToLower() == "log")
                                    {
                                        if (n1a.Value.IndexOf('\\') >= 0 || n1a.Value.IndexOf('/') >= 0) // looks like file path
                                        {
                                            sb1 = Path.GetDirectoryName(n1a.Value);

                                            if (Directory.Exists(sb1))
                                            {
                                                if (n1a.Value == sb1) // only dir was specified - append filename
                                                    sb1 = Path.Combine(sb1, Path.GetFileNameWithoutExtension(System.Reflection.Assembly.GetExecutingAssembly().Location) + ".log");
                                                else sb1 = n1a.Value;

                                                _log_type = 1; // file
                                                if (_log_init(sb1)) _log = true;
                                            };
                                        }
                                        else if (AgentBase._is_true(n1a)) // defaults to Application system log
                                        {
                                            _log_type = 0;
                                            if (_log_init(string.Empty)) _log = true;
                                        }
                                        else // named system log
                                        {
                                            _log_type = 0;
                                            if (_log_init(n1a.Name.Trim())) _log = true;
                                        };
                                    };
                                };
                            };

                            // signer section
                            foreach (XmlNode n2 in n1.ChildNodes)
                            {
                                if (n2.NodeType == XmlNodeType.Element && (n2.Name.ToLower() == "domains" || n2.Name.ToLower() == "domain"))
                                {
                                    foreach (XmlNode n3 in n2.ChildNodes)
                                    {
                                        if (_dom_key != null && Array.BinarySearch<string>(_dom_key, n3.Value.ToLower().Trim()) >= 0) continue; // first occurence wins
                                        else
                                        {
                                            DKIM.Signer ds; DKIM.Signer.HeaderOption dsho;

                                            try
                                            {
                                                ds = new DKIM.Signer(); // set some defaults
                                                ds.DomainName = n3.Name.ToLower().Trim();
                                                ds.SignatureAlgorithm = DKIM.SignatureAlgorithm.Sha1RSA;
                                                ds.HeaderCanonicalization = DKIM.Canonicalization.Algorithm.Simple;
                                                ds.BodyCanonicalization = DKIM.Canonicalization.Algorithm.Simple;

                                                foreach (XmlNode n4 in n3.ChildNodes)
                                                {
                                                    if (n4.NodeType == XmlNodeType.Element && (n4.Name.ToLower() == "headers" || n4.Name.ToLower() == "header"))
                                                    {
                                                        foreach (XmlAttribute n4a in n4.Attributes)
                                                        {
                                                            if ((n4a.Name.ToLower() == "signall" || n4a.Name.ToLower() == "all") && AgentBase._is_true(n4a)) { ds.HeaderOptions.Clear(); ds.SignAllHeaders = true; };
                                                        };

                                                        if (!ds.SignAllHeaders) // no point iterating futher if set
                                                        {
                                                            foreach (XmlNode n5 in n4.ChildNodes)
                                                            {
                                                                dsho = new DKIM.Signer.HeaderOption(n5.Name.ToLower().Trim(), DKIM.Signer.HeaderOption.Trait.None);

                                                                foreach (XmlAttribute n5a in n5.Attributes)
                                                                {
                                                                    if ((n5a.Name.ToLower() == "signalloccurences" || n5a.Name.ToLower() == "signall" || n5a.Name.ToLower() == "a") && !AgentBase._is_false(n5a)) dsho.Traits = dsho.Traits | DKIM.Signer.HeaderOption.Trait.SignAllOccurences;
                                                                    else if ((n5a.Name.ToLower() == "omitifmissing" || n5a.Name.ToLower() == "omitmissing" || n5a.Name.ToLower() == "m") && !AgentBase._is_false(n5a)) dsho.Traits = dsho.Traits | DKIM.Signer.HeaderOption.Trait.OmitIfMissing;
                                                                    else if ((n5a.Name.ToLower() == "signemptyvalue" || n5a.Name.ToLower() == "signempty" || n5a.Name.ToLower() == "e") && !AgentBase._is_false(n5a)) dsho.Traits = dsho.Traits | DKIM.Signer.HeaderOption.Trait.SignEmptyValue;
                                                                };

                                                                ds.SignAllHeaders = false;
                                                                ds.HeaderOptions.Add(dsho);
                                                            };
                                                        };
                                                    }
                                                    else if (n4.NodeType == XmlNodeType.Element && (n4.Name.ToLower() == "selectorname" || n4.Name.ToLower() == "selector")) ds.SelectorName = n4.InnerText;
                                                    else if (n4.NodeType == XmlNodeType.Element && (n4.Name.ToLower() == "timestamp" || n4.Name.ToLower() == "ts"))
                                                    {
                                                        ds.EnableTimestamping = true;

                                                        foreach (XmlAttribute n4a in n4.Attributes)
                                                        {
                                                            if (n4a.Name.ToLower() == "validity" || n4a.Name.ToLower() == "vts" || n4a.Name.ToLower() == "v")
                                                            {
                                                                TimeSpan vts;

                                                                if (TimeSpan.TryParse(n4a.Value, out vts)) ds.SignatureValidityPeriod = vts;
                                                            };
                                                        };
                                                    }
                                                    else if (n4.NodeType == XmlNodeType.Element && (n4.Name.ToLower() == "privatekey" || n4.Name.ToLower() == "pvk"))
                                                    {
                                                        byte[] pvk1, pvk2; bool pvkv = false;

                                                        pvk1 = System.Convert.FromBase64String(n4.InnerText);

                                                        foreach (XmlAttribute n4a in n4.Attributes)
                                                        {
                                                            if (n4a.Name.ToLower() == "protectionlevel" || n4a.Name.ToLower() == "protection" || n4a.Name.ToLower() == "prot" || n4a.Name.ToLower() == "p")
                                                            {
                                                                switch (n4a.Value.ToLower().Trim())
                                                                {
                                                                    case "dpapi.machine":
                                                                    case "machine":
                                                                    case "mach":
                                                                    case "m":
                                                                        pvk2 = System.Security.Cryptography.ProtectedData.Unprotect(pvk1, null, System.Security.Cryptography.DataProtectionScope.LocalMachine);
                                                                        ds.PrivateKeyDER = pvk2;
                                                                        Array.Clear(pvk1, 0, pvk1.Length); pvk1 = null;
                                                                        Array.Clear(pvk2, 0, pvk2.Length); pvk2 = null;
                                                                        pvkv = true;
                                                                        break;
                                                                    case "dpapi.user":
                                                                    case "user":
                                                                    case "r":
                                                                        pvk2 = System.Security.Cryptography.ProtectedData.Unprotect(pvk1, null, System.Security.Cryptography.DataProtectionScope.LocalMachine);
                                                                        ds.PrivateKeyDER = pvk2;
                                                                        Array.Clear(pvk1, 0, pvk1.Length); pvk1 = null;
                                                                        Array.Clear(pvk2, 0, pvk2.Length); pvk2 = null;
                                                                        pvkv = true;
                                                                        break;
                                                                    case "none":
                                                                    case "n":
                                                                        pvk2 = pvk1;
                                                                        ds.PrivateKeyDER = pvk1;
                                                                        Array.Clear(pvk1, 0, pvk1.Length); pvk1 = null;
                                                                        pvkv = true;
                                                                        break;
                                                                    default: throw new Exception();
                                                                };
                                                            };
                                                        };

                                                        if (!pvkv) throw new Exception(); // protection level MUST be set
                                                    }
                                                    else if (n4.NodeType == XmlNodeType.Element && (n4.Name.ToLower() == "canonicalization" || n4.Name.ToLower() == "canonicalisation" || n4.Name.ToLower() == "canon"))
                                                    {
                                                        foreach (XmlAttribute n4a in n4.Attributes)
                                                        {
                                                            if (n4a.Name.ToLower() == "h")
                                                            {
                                                                if (n4a.Value.ToLower().Trim() == "relaxed" || n4a.Value.ToLower().Trim() == "rel" || n4a.Value.ToLower().Trim() == "r")
                                                                {
                                                                    ds.HeaderCanonicalization = DKIM.Canonicalization.Algorithm.Relaxed;
                                                                }
                                                                else if (n4a.Value.ToLower().Trim() == "simple" || n4a.Value.ToLower().Trim() == "simp" || n4a.Value.ToLower().Trim() == "s")
                                                                {
                                                                    ds.HeaderCanonicalization = DKIM.Canonicalization.Algorithm.Simple;
                                                                }
                                                                else throw new Exception();
                                                            }
                                                            else if (n4a.Name.ToLower() == "b")
                                                            {
                                                                if (n4a.Value.ToLower().Trim() == "relaxed" || n4a.Value.ToLower().Trim() == "rel" || n4a.Value.ToLower().Trim() == "r")
                                                                {
                                                                    ds.BodyCanonicalization = DKIM.Canonicalization.Algorithm.Relaxed;
                                                                }
                                                                else if (n4a.Value.ToLower().Trim() == "simple" || n4a.Value.ToLower().Trim() == "simp" || n4a.Value.ToLower().Trim() == "s")
                                                                {
                                                                    ds.BodyCanonicalization = DKIM.Canonicalization.Algorithm.Simple;
                                                                }
                                                                else throw new Exception();
                                                            };
                                                        };
                                                    }
                                                    else if (n4.NodeType == XmlNodeType.Element && (n4.Name.ToLower() == "agentid" || n4.Name.ToLower() == "auid"))
                                                    {
                                                        ds.AgentID = n4.InnerText.Trim();
                                                    }
                                                    else if (n4.NodeType == XmlNodeType.Element && (n4.Name.ToLower() == "signaturealgorithm" || n4.Name.ToLower() == "algorithm"))
                                                    {
                                                        switch (n4.InnerText.ToLower().Trim())
                                                        {
                                                            case "rsa-sha1":
                                                                ds.SignatureAlgorithm = DKIM.SignatureAlgorithm.Sha1RSA;
                                                                break;
                                                            case "rsa-sha256":
                                                                ds.SignatureAlgorithm = DKIM.SignatureAlgorithm.Sha256RSA;
                                                                break;
                                                            default: throw new Exception();
                                                        };
                                                    }
                                                    else continue;
                                                };

                                                if (ds.IsPrivateKeyPresent && ds.DomainName.Length > 0 && ds.SelectorName.Length > 0 && (ds.SignAllHeaders || ds.HeaderOptions.Count > 0) && ds.SignatureAlgorithm != DKIM.SignatureAlgorithm.Unknown)
                                                {
                                                    // all looks sound

                                                    Array.Resize<string>(ref _dom_key, (_dom_key == null ? 1 : _dom_key.Length + 1));
                                                    Array.Resize<int>(ref _dom_ord, _dom_key.Length);
                                                    Array.Resize<DKIM.Signer>(ref _dom_signer, _dom_key.Length);

                                                    _dom_key[_dom_key.Length - 1] = ds.DomainName;
                                                    _dom_ord[_dom_key.Length - 1] = _dom_key.Length - 1;
                                                    _dom_signer[_dom_key.Length - 1] = ds;

                                                    Array.Sort(_dom_key, _dom_ord);
                                                }
                                                else throw new Exception(); // section invalid
                                            }
                                            catch { continue; }; // section invalid
                                        };
                                    };
                                }
                                else continue; // unrecognized
                            };

                            return true; // ignore other sections
                        };
                    };
                };
            }
            catch
            { return false; };

            return true;
        }

        private bool _log_init(string _location)
        {
            if (_log_type == 1) // file
            {
                try
                {
                    _log_obj = new StreamWriter(_location, File.Exists(_location), System.Text.Encoding.UTF8);
                    if (!((StreamWriter)_log_obj).BaseStream.CanWrite) { ((StreamWriter)_log_obj).Close(); return false; };
                }
                catch { return false; };
            }
            else if (_log_type == 0) // system log
            {
                try
                {
                    if (_location == null || _location.Length == 0)
                    {
                        _log_obj = new EventLog("Application");

                        try { if (!EventLog.SourceExists("Arclight")) EventLog.CreateEventSource("Arclight", "Application"); ((EventLog)_log_obj).Source = "Arclight"; } // try set source
                        catch { }; // не очень-то и хотелось
                    }
                    else // named log
                    {
                        try
                        {
                            if (!EventLog.Exists(_location))
                            {
                                EventLog.CreateEventSource("Arclight", _location);
                            }
                            else
                            {
                                _log_obj = new EventLog(_location);

                                try { if (!EventLog.SourceExists("Arclight")) EventLog.CreateEventSource("Arclight", _location); ((EventLog)_log_obj).Source = "Arclight"; } // try set source
                                catch { }; // не очень-то и хотелось
                            };
                        }
                        catch { return false; };
                    };
                }
                catch { return false; };
            }
            else return false; // bullshit

            return true;
        }

        private void _log_post(string msg, bool d, bool w, bool e)
        {
            if (_log_obj == null || msg == null || msg.Trim().Length == 0) return; // nothing or nowhere

            try
            {
                if (d && _debug)
                {
                    if (_log_obj.GetType() == typeof(EventLog)) ((EventLog)_log_obj).WriteEntry("[DEBUG] " + msg, EventLogEntryType.Information);
                    else if (_log_obj.GetType() == typeof(StreamWriter)) ((StreamWriter)_log_obj).WriteLine("[" + DateTime.Now.ToString("o") + "] [DEBUG] " + msg); // iso timestamp
                }
                else if (e)
                {
                    if (_log_obj.GetType() == typeof(EventLog)) ((EventLog)_log_obj).WriteEntry(msg, EventLogEntryType.Error);
                    else if (_log_obj.GetType() == typeof(StreamWriter)) ((StreamWriter)_log_obj).WriteLine("[" + DateTime.Now.ToString("o") + "] [ERROR] " + msg);
                }
                else if (w)
                {
                    if (_log_obj.GetType() == typeof(EventLog)) ((EventLog)_log_obj).WriteEntry(msg, EventLogEntryType.Warning);
                    else if (_log_obj.GetType() == typeof(StreamWriter)) ((StreamWriter)_log_obj).WriteLine("[" + DateTime.Now.ToString("o") + "] [WARN] " + msg);
                }
                else
                {
                    if (_log_obj.GetType() == typeof(EventLog)) ((EventLog)_log_obj).WriteEntry(msg, EventLogEntryType.Information);
                    else if (_log_obj.GetType() == typeof(StreamWriter)) ((StreamWriter)_log_obj).WriteLine("[" + DateTime.Now.ToString("o") + "] " + msg);
                };

                if (_log_obj.GetType() == typeof(StreamWriter)) ((StreamWriter)_log_obj).Flush(); // сука blyat
            }
            catch { };
        }
    }
}
