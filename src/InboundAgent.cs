using System;
using Microsoft.Win32;
using System.IO;
using System.Collections.Generic;
using System.Diagnostics;
using System.Xml;
using System.Text;

#if EXCHANGE14
    using Microsoft.Exchange.Data.Transport;
    using Microsoft.Exchange.Data.Transport.Smtp;
    using Microsoft.Exchange.Data.Transport.Routing;
#endif

namespace Arclight
{
    internal static class AgentBase
    {
        private static readonly object _guard = new object();
        private static XmlDocument _cfg;
        private static ushort _cfg_flags = 0;

        public static bool LoadConfiguration() { return LoadConfiguration(true); }
        public static bool LoadConfiguration(bool ReplaceCurrent)
        {
            XmlDocument iv;

            lock (_guard)
            {
                iv = _adjust_cfg(null);

                if ((iv != null && _cfg != null && ReplaceCurrent) || (iv != null && _cfg == null))
                {
                    _cfg = iv;

                    return true;
                }
                else if (iv != null && _cfg != null && !ReplaceCurrent) return true;
                else return false;
            };
        }

        public static bool SaveConfiguration()
        {
            lock (_guard)
            {
                if (_cfg == null) return false;

                _adjust_cfg(_cfg);

                if ((_cfg_flags & 8) == 8) return true;
                else return false;
            };
        }

        public static bool IsConfigurationPresent { get { lock (_guard) { if (_cfg_flags != 0 && _cfg != null) return true; else return false; }; } }
    
        public static XmlDocument Configuration
        {
            get
            {
                lock (_guard)
                {
                    if (_cfg_flags != 0 && _cfg == null) return null;
                    else if (_cfg_flags == 0)
                    {
                        _cfg = _adjust_cfg(null);

                        if (_cfg != null) return _cfg; else return null;
                    }
                    else return _cfg;
                };
            }
            set
            {
                lock (_guard)
                {
                    if (value == null)
                    {
                        _cfg_flags = 0;
                        _cfg = null;
                    }
                    else _cfg = value;
                };
            }
        }
    
        private static XmlDocument _adjust_cfg(XmlDocument _existing)
        {
            XmlDocument rv = null;
            string sb1 = null;
            long nb1 = 0;
            bool f;

            // check pointer file first
            try
            {
                if (File.Exists(System.Reflection.Assembly.GetExecutingAssembly().Location + ".cfg"))
                {
                    using (FileStream fs = new FileStream(System.Reflection.Assembly.GetExecutingAssembly().Location + ".cfg", FileMode.Open))
                    {
                        if (fs.Length <= 1024) // pointer should be relatively small
                        {
                            using (TextReader tr = new StreamReader(fs, true))
                            {
                                sb1 = tr.ReadLine();

                                switch (sb1.Substring(0, sb1.IndexOf(':')).Trim().ToLower())
                                {
                                    case "registry":
                                    case "reg":
                                        nb1 = 1;
                                        sb1 = sb1.Substring(sb1.IndexOf(':') + 1).Trim();
                                        break;
                                    case "file":
                                        nb1 = 2;
                                        sb1 = sb1.Substring(sb1.IndexOf(':') + 1).Trim();
                                        break;
                                    default: break;
                                };
                            };
                        }
                        else nb1 = 0;
                    };
                }
                else nb1 = 0;
            }
            catch { };

            if (nb1 <= 0) { nb1 = 1; sb1 = "hklm/software/arclight/configuration"; }; // set default pointer

            try
            {
                if (nb1 == 1) // registry
                {
                    RegistryKey k;

                    sb1 = sb1.Replace('/', '\\');

                    if (sb1.Substring(0, sb1.IndexOf('\\')).ToLower() == "hkcr" || sb1.Substring(0, sb1.IndexOf('\\')).ToLower() == "hkey_classes_root")
                        k = Registry.ClassesRoot.OpenSubKey(sb1.Substring(sb1.IndexOf('\\') + 1));
                    else if (sb1.Substring(0, sb1.IndexOf('\\')).ToLower() == "hkcu" || sb1.Substring(0, sb1.IndexOf('\\')).ToLower() == "hkey_current_user")
                        k = Registry.CurrentUser.OpenSubKey(sb1.Substring(sb1.IndexOf('\\') + 1));
                    else if (sb1.Substring(0, sb1.IndexOf('\\')).ToLower() == "hklm" || sb1.Substring(0, sb1.IndexOf('\\')).ToLower() == "hkey_local_machine")
                        k = Registry.LocalMachine.OpenSubKey(sb1.Substring(sb1.IndexOf('\\') + 1));
                    else if (sb1.Substring(0, sb1.IndexOf('\\')).ToLower() == "hku" || sb1.Substring(0, sb1.IndexOf('\\')).ToLower() == "hkey_users")
                        k = Registry.Users.OpenSubKey(sb1.Substring(sb1.IndexOf('\\') + 1));
                    else if (sb1.Substring(0, sb1.IndexOf('\\')).ToLower() == "hkcc" || sb1.Substring(0, sb1.IndexOf('\\')).ToLower() == "hkey_current_config")
                        k = Registry.CurrentConfig.OpenSubKey(sb1.Substring(sb1.IndexOf('\\') + 1));
                    else return null;

                    _cfg_flags = 4; // !L !F !R !S

                    if (_existing == null) // load
                    {
                        if (k.GetValue(string.Empty) != null && k.GetValueKind(string.Empty) == RegistryValueKind.String) // try unicode-string in (default)
                        {
                            rv = new XmlDocument();
                            rv.LoadXml((string)k.GetValue(string.Empty));
                            _cfg_flags = 1 + 4; // L !F R !S
                        }
                        else if (k.GetValue("Data") != null && k.GetValueKind("Data") == RegistryValueKind.String) // try unicode-string in "Data"
                        {
                            rv = new XmlDocument();
                            rv.LoadXml((string)k.GetValue("Data"));
                            _cfg_flags = 1 + 4; // L !F R !S
                        }
                        else if (k.GetValue("Data") != null && k.GetValueKind("Data") == RegistryValueKind.Binary) // try binary in "Data"
                        {
                            rv = new XmlDocument();
                            rv.LoadXml(System.Text.Encoding.UTF8.GetString((byte[])k.GetValue("Data")));
                            _cfg_flags = 1 + 4; // L !F R !S
                        }
                        else return null; // no rv
                    }
                    else // store
                    {
                        if (k.GetValue("Data") != null && k.GetValueKind("Data") == RegistryValueKind.String)
                        {
                            k.SetValue("Data", _existing.InnerText, RegistryValueKind.String);
                            _cfg_flags = 4 + 8; // !L !F R S
                        }
                        else if (k.GetValue("Data") != null && k.GetValueKind("Data") == RegistryValueKind.Binary)
                        {
                            k.SetValue("Data", System.Text.Encoding.UTF8.GetBytes(_existing.InnerText), RegistryValueKind.Binary);
                            _cfg_flags = 4 + 8; // !L !F R S
                        }
                        else
                        {
                            k.SetValue("Data", System.Text.Encoding.UTF8.GetBytes(_existing.InnerText), RegistryValueKind.Binary);
                            _cfg_flags = 4 + 8; // !L !F R S
                        };

                        return null; // no rv
                    };
                }
                else if (nb1 == 2) // file
                {
                    _cfg_flags = 2; // !L F !R !S

                    if (_existing == null) // load
                    {
                        if (File.Exists(sb1) && (new FileInfo(sb1)).Length <= 64 * 1024 * 1024) // exists and reasonable length
                        {
                            byte[] bb = File.ReadAllBytes(sb1);
                            f = false;

                            rv = new XmlDocument();

                            // try hard
                            try { if (!f) { rv.LoadXml(System.Text.Encoding.UTF8.GetString(bb)); f = true; }; } catch { };
                            try { if (!f) { rv.LoadXml(System.Text.Encoding.UTF32.GetString(bb)); f = true; }; } catch { };
                            try { if (!f) { rv.LoadXml(System.Text.Encoding.ASCII.GetString(bb)); f = true; }; } catch { };

                            if (f) _cfg_flags = 1 + 2; // L F !R !S
                            else return null;
                        }
                        else // store
                        {
                            try
                            {
                                File.WriteAllBytes(sb1, System.Text.Encoding.UTF8.GetBytes(_existing.InnerText));

                                _cfg_flags = 2 + 8; // !L F !R S
                            }
                            catch { };

                            return null; // no rv
                        };
                    }
                    else return null; // no rv
                }
            }
            catch { return null; };

            return rv; // return always
        }

        public static bool _is_true(XmlNode _e) // seeks "true", "yes", "1" etc
        {
            string v; double v2;

            try
            {
                if (_e.Value != null)
                {
                    v = _e.Value.ToLower().Trim();

                    if (v == "yes" || v == "true") return true;

                    if (double.TryParse(v, out v2)) return v2 == 0 ? false : true;

                    return false;
                }
                else
                {
                    v = _e.InnerText;
                    if (v.StartsWith("\"")) v = v.Substring(1);
                    if (v.EndsWith("\"")) v = v.Substring(0, v.Length - 1);

                    if (v == "yes" || v == "true") return true;

                    if (double.TryParse(v, out v2)) return v2 == 0 ? false : true;

                    return false;
                };
            }
            catch { return false; };
        }

        public static bool _is_false(XmlNode _e) // seeks "false", "no", "0" etc
        {
            string v; double v2;

            try
            {
                if (_e.Value != null)
                {
                    v = _e.Value.ToLower().Trim();

                    if (v == "no" || v == "false") return true;

                    if (double.TryParse(v, out v2)) return v2 == 0 ? false : true;

                    return false;
                }
                else
                {
                    v = _e.InnerText;
                    if (v.StartsWith("\"")) v = v.Substring(1);
                    if (v.EndsWith("\"")) v = v.Substring(0, v.Length - 1);

                    if (v == "yes" || v == "true") return true;

                    if (double.TryParse(v, out v2)) return v2 == 0 ? false : true;

                    return false;
                };
            }
            catch { return false; };
        }
    }

    public sealed class InboundAgentFactory : SmtpReceiveAgentFactory
    {
        public override SmtpReceiveAgent CreateAgent(SmtpServer server)
        {
            return new InboundAgent();
        }
    }
    public sealed class InboundAgent : SmtpReceiveAgent
    {
        public enum ResponseAction : short { Reject = -2, Quarantine = -1, Accept = 0, SetHeader = 1, ModifySCL = 2 }

        public abstract class ActionParams{ } // abstract
        public class RejectParams : ActionParams
        {
            public string Code;
            public string ExtendedCode;
            public string Elaboration;
        }
        public class QuarantineParams : ActionParams
        {
            public string[] Recipient; // not working yet
            public string QuarantineReason;
        }
        public class SetHeaderParams : ActionParams
        {
            public string Header;
            public string Value;
            public bool Append;
        }
        public class ModifySCLParams : ActionParams
        {
            public short Modifier;
            public bool IsRelative;
        }

        private string[] _dom_key;
        private int[] _dom_ord;
        private ResponseAction[] _dom_pass_act, _dom_fail_act, _dom_unsig_act;
        private ActionParams[] _dom_pass_params, _dom_fail_params, _dom_unsig_params;
        private ResponseAction _default_pass_act, _default_fail_act, _default_unsig_act;
        private ActionParams _default_pass_params, _default_fail_params, _default_unsig_params;

        private DKIM.Verifier _verifier; // centerpiece of this bullshit

        private bool _debug = false;
        private bool _log = false;
        private byte _log_type = 0;
        private object _log_obj;

        private bool _ar_header;

        private bool _stats;

        ~InboundAgent()
        {
            if (_log_obj != null && _log_obj.GetType() == typeof(StreamWriter))
            {
                try { ((StreamWriter)_log_obj).Flush(); } catch { };
                try { ((StreamWriter)_log_obj).Close(); } catch { };
            }
            else if (_log_obj != null && _log_obj.GetType() == typeof(EventLog))
            {
                try { ((EventLog)_log_obj).Close(); } catch { };
            };
        }

        public InboundAgent()
        {
            bool lb;    
            DateTime ts0, ts1;

            ts0 = DateTime.Now;

            lb = _load_cfg();

            ts1 = DateTime.Now;

            if (lb) // at least one valid section loaded
            {
                _verifier = new DKIM.Verifier();

                // configuration validated - register handler
                this.OnEndOfData += new EndOfDataEventHandler(OnEndOfDataHandler);

                _log_post("Initialization completed in " + Math.Round(ts1.Subtract(ts0).TotalMilliseconds, 0).ToString() + " ms", true, false, false);
            }
            else
            {
                _log_post("No valid sections was loaded", true, false, false);

                return; // no valid configuration - agent going inert
            };
        }

        public void OnEndOfDataHandler(ReceiveMessageEventSource source, EndOfDataEventArgs e)
        {
            try
            {
                string sb; int nb; byte[] bb1, bb2;
                DKIM.Verifier.Result vr;

                if (e.MailItem.Message.TnefPart != null) // tnefs or system msgs are ignored
                {
                    _log_post("Inbound message [MsgID " + e.MailItem.Message.MessageId + ") is of TNEF format and was ignored", true, false, false);
                    return;
                }
                else if (e.MailItem.Message.IsSystemMessage)
                {
                    _log_post("Inbound message [MsgID " + e.MailItem.Message.MessageId + ") is system message and was ignored", true, false, false);
                    return;
                };

                sb = e.MailItem.FromAddress.DomainPart.ToLower();

                _log_post("Inbound message [MsgID " + e.MailItem.Message.MessageId + ") received from [" + sb + "]", true, false, false);

                Stream rmsg; string msg; System.Text.Encoding enc = null; bool wb = false;

                // mumbo-jumbo for botched encodings
                using (MemoryStream ms = new MemoryStream())
                {
                    // extract headers
                    ms.Seek(0, SeekOrigin.Begin);
                    e.MailItem.Message.RootPart.Headers.WriteTo(ms, new Microsoft.Exchange.Data.Mime.EncodingOptions("us-ascii", "en-US", Microsoft.Exchange.Data.Mime.EncodingFlags.EnableRfc2231));

                    // extract body
                    rmsg = e.MailItem.Message.MimeDocument.RootPart.GetRawContentReadStream();
                    bb2 = new byte[rmsg.Length]; rmsg.Read(bb2, 0, bb2.Length);

                    bb1 = new byte[ms.Length + 2 + bb2.Length]; // headers + boundary + body
                    ms.Seek(0, SeekOrigin.Begin); ms.Read(bb1, 0, (int)ms.Length);
                    bb1[ms.Length] = (byte)'\r'; bb1[ms.Length + 1] = (byte)'\n';
                    Array.Copy(bb2, 0, bb1, ms.Length + 2, bb2.Length);

                    // reassemble message
                    msg = DKIM.Encoding.DecodeMessage(bb1, ref enc);
                };

                try // e.MailItem.Message.Body.CharsetName ?
                {
                    if (e.MailItem.Message.Body.CharsetName.ToLower() != enc.EncodingName.ToLower())
                    {
                        _log_post("Detected encoding [" + enc.EncodingName + "], Exchange-indicated encoding is [" + e.MailItem.Message.Body.CharsetName + "]", true, false, false);
                    }
                    else if (enc.GetType() != typeof(System.Text.ASCIIEncoding))
                    {
                        _log_post("Detected non-standard encoding [" + enc.EncodingName + "]", true, false, false);
                    };
                }
                catch { };

                // verifier call
                try
                { vr = _verifier.VerifyMessage(msg); }
                catch (Exception e0)
                {
                    _log_post("UNEXPECTED " + e0.ToString() + " : \"" + e0.Message + "\"", false, false, true);

                    try { _log_post("MSG [" + msg + "]", true, false, false); } catch { };

                    return;
                };

                try { _log_post("MSG [" + msg + "]", true, false, false); } catch { };

                _log_post("Verification results - [" + vr.PrimaryCode.ToString() + " / " + vr.SecondaryCode.ToString() + "], elapsed " + vr.ElapsedMillis.ToString() + " ms", true, false, false);
                if (vr.PrimaryCode == DKIM.Verifier.Result.Code.TEMPFAIL)
                {
                    _log_post("TEMPFAIL for [MsgID " + e.MailItem.Message.MessageId + "], SC [" + vr.SecondaryCode.ToString() + "]", false, true, false);
                };

                if (false && _stats) // TODO implement!
                {
                    /*
                    XmlDocument cfg = _adjust_cfg(null); XmlElement xn1, xn2;
                    */
                };

                ResponseAction ra;
                ActionParams rap;

                // search domain section or use default section
                if (_dom_key != null && _dom_key.Length > 0) nb = Array.BinarySearch<string>(_dom_key, sb);
                else nb = -1;

                if (nb >= 0)
                {
                    if (vr.PrimaryCode == DKIM.Verifier.Result.Code.PERMFAIL && vr.SecondaryCode == DKIM.Verifier.Result.ExtendedCode.NoSignature)
                    {
                        ra = _dom_unsig_act[_dom_ord[nb]]; rap = _dom_unsig_params[_dom_ord[nb]];
                    }
                    else if (vr.PrimaryCode == DKIM.Verifier.Result.Code.PERMFAIL || vr.PrimaryCode == DKIM.Verifier.Result.Code.TEMPFAIL)
                    {
                        ra = _dom_fail_act[_dom_ord[nb]]; rap = _dom_fail_params[_dom_ord[nb]];
                    }
                    else
                    {
                        ra = _dom_pass_act[_dom_ord[nb]]; rap = _dom_pass_params[_dom_ord[nb]];
                    };

                    _log_post("Response action - [" + ra.ToString() + "] as configured for domain [" + sb + "]", true, false, false);
                }
                else
                {
                    if (vr.PrimaryCode == DKIM.Verifier.Result.Code.PERMFAIL && vr.SecondaryCode == DKIM.Verifier.Result.ExtendedCode.NoSignature)
                    {
                        ra = _default_unsig_act; rap = _default_unsig_params;
                    }
                    else if (vr.PrimaryCode == DKIM.Verifier.Result.Code.PERMFAIL || vr.PrimaryCode == DKIM.Verifier.Result.Code.TEMPFAIL)
                    {
                        ra = _default_fail_act; rap = _default_fail_params;
                    }
                    else
                    {
                        ra = _default_pass_act; rap = _default_pass_params;
                    };

                    _log_post("Response action - [" + ra.ToString() + "]", true, false, false);
                };

                if (ra == ResponseAction.ModifySCL)
                {
                    string scls; short scl = 0;

                    scls = DKIM.GetHeader(ref msg, "X-MS-Exchange-Organization-SCL");
                    if (scls != null && scls.Trim().Length > 0)
                    {
                        if (!short.TryParse(scls, out scl)) scl = 0;
                    }
                    else scl = 0;

                    if (((ModifySCLParams)rap).IsRelative) scl = (short)(scl + ((ModifySCLParams)rap).Modifier);
                    else scl = ((ModifySCLParams)rap).Modifier;

                    // clamp
                    if (scl < -1) scl = -1;
                    else if (scl > 9) scl = 9;

                    if (e.MailItem.Message.RootPart.Headers.FindFirst("X-MS-Exchange-Organization-SCL") != null)
                    {
                        e.MailItem.Message.RootPart.Headers.FindFirst("X-MS-Exchange-Organization-SCL").Value = scl.ToString();
                    }
                    else
                    {
                        e.MailItem.Message.RootPart.Headers.AppendChild(new Microsoft.Exchange.Data.Mime.TextHeader("X-MS-Exchange-Organization-SCL", scl.ToString()));
                    };
                }
                else if (ra == ResponseAction.Quarantine) { } // TODO !
                else if (ra == ResponseAction.Reject)
                {
                    SmtpResponse rr = new SmtpResponse
                            (
                                ((RejectParams)rap).Code,
                                ((RejectParams)rap).ExtendedCode,
                                ((RejectParams)rap).Elaboration
                            );

                    source.RejectMessage(rr); wb = false;
                }
                else if (ra == ResponseAction.SetHeader)
                {
                    string hk, hv;
                    
                    hk = ((SetHeaderParams)rap).Header;
                    if (e.MailItem.Message.RootPart.Headers.FindFirst(hk) != null)
                    {
                        if (((SetHeaderParams)rap).Append) hv = e.MailItem.Message.RootPart.Headers.FindFirst(hk).Value;
                        else hv = string.Empty;

                        if (hv.Length > 0) hv = hv + "; " + ((SetHeaderParams)rap).Value;
                        else hv = ((SetHeaderParams)rap).Value;

                        e.MailItem.Message.RootPart.Headers.FindFirst(hk).Value = hv;
                    }
                    else
                    {
                        e.MailItem.Message.RootPart.Headers.AppendChild(new Microsoft.Exchange.Data.Mime.TextHeader("X-MS-Exchange-Organization-SCL", ((SetHeaderParams)rap).Value));    
                    };
                };

                if (_ar_header)
                {
                    string arv, vrs;

                    if (vr.PrimaryCode == DKIM.Verifier.Result.Code.PERMFAIL && vr.SecondaryCode == DKIM.Verifier.Result.ExtendedCode.NoSignature)
                    {
                        vrs = "dkim=none";
                    }
                    else if (vr.PrimaryCode == DKIM.Verifier.Result.Code.SUCCESS)
                    {
                        vrs = "dkim=pass";
                    }
                    else if ((vr.PrimaryCode == DKIM.Verifier.Result.Code.PERMFAIL || vr.PrimaryCode == DKIM.Verifier.Result.Code.TEMPFAIL) && vr.SecondaryCode != DKIM.Verifier.Result.ExtendedCode.None)
                    {
                        vrs = "dkim=fail (" + vr.SecondaryCode.ToString() + ")";
                    }
                    else vrs = "dkim=fail";

                    if (e.MailItem.Message.RootPart.Headers.FindFirst("Authentication-Results") != null)
                    {
                        arv = e.MailItem.Message.RootPart.Headers.FindFirst("Authentication-Results").Value;

                        if (arv.Length > 0) arv = arv + "; " + vrs;
                        else arv = vrs;

                        e.MailItem.Message.RootPart.Headers.FindFirst("Authentication-Results").Value = arv;
                    }
                    else
                    {
                        arv = vrs;

                        e.MailItem.Message.RootPart.Headers.AppendChild(new Microsoft.Exchange.Data.Mime.TextHeader("Authentication-Results", arv));
                    };
                };

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
                _log_post("EXCEPTION while verifying [MsgID " + e.MailItem.Message.MessageId + "] - " + e2.ToString() + ": \"" + e2.Message + "\"]", false, false, true);
            };
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

        private void _cfg_read_domain_section(ref XmlNode n, ref ResponseAction u, ref ResponseAction p, ref ResponseAction f, ref ActionParams up, ref ActionParams pp, ref ActionParams fp)
        {
            byte bb = 0;

            if (n.ChildNodes.Count == 0) // defaults to accept
            {
                u = ResponseAction.Accept;
                p = ResponseAction.Accept;
                f = ResponseAction.Accept;

                return;
            };

            foreach (XmlNode n2 in n.ChildNodes)
            {
                if (n2.Name.ToLower() == "unsigned" || n2.Name.ToLower() == "unsig" || n2.Name.ToLower() == "u") bb = 1;
                else if (n2.Name.ToLower() == "pass" || n2.Name.ToLower() == "p") bb = 2;
                else if (n2.Name.ToLower() == "fail" || n2.Name.ToLower() == "f") bb = 3;
                else { bb = 0; continue; }; // unrecognized

                if (n2.Attributes.Count == 0 || n2.Attributes["action"] == null)
                {
                    if (bb == 1) u = ResponseAction.Accept;
                    else if (bb == 2) p = ResponseAction.Accept;
                    else if (bb == 3) f = ResponseAction.Accept;
                }
                else
                {
                    switch (n2.Attributes["action"].Value.ToLower().Trim())
                    {
                        case "accept":
                        case "a":
                            if (bb == 1) u = ResponseAction.Accept;
                            else if (bb == 2) p = ResponseAction.Accept;
                            else if (bb == 3) f = ResponseAction.Accept;
                            break;
                        case "reject":
                        case "r":
                            RejectParams rp0 = new RejectParams();
                            rp0.Code = n2["Code"] != null ? n2["code"].Value : "550";
                            rp0.ExtendedCode = n2["ExtendedCode"] != null ? n2["ExtendedCode"].Value : "5.7.1";
                            rp0.Elaboration = n2["Elaboration"] != null ? n2["Elaboration"].Value : "rejected due to policy"; // because reasons

                            if (bb == 1) { u = ResponseAction.Reject; up = rp0; }
                            else if (bb == 2) { p = ResponseAction.Reject; pp = rp0; }
                            else if (bb == 3) { f = ResponseAction.Reject; fp = rp0; }

                            break;
                        case "quarantine":
                        case "q":
                            QuarantineParams qp0 = new QuarantineParams();
                            if (n2["recipients"] == null || n2["recipients"].ChildNodes.Count == 0) throw new Exception(); // section invalid
                            qp0.Recipient = new string[n2.ChildNodes.Count];
                            for (int i = 0; i < n2.ChildNodes.Count; ++i) qp0.Recipient[i] = n2.ChildNodes[i].Value;
                            if (n2["reason"] != null) qp0.QuarantineReason = n2["reason"].Value; // may be absent

                            if (bb == 1) { u = ResponseAction.Quarantine; up = qp0; }
                            else if (bb == 2) { p = ResponseAction.Quarantine; pp = qp0; }
                            else if (bb == 3) { f = ResponseAction.Quarantine; fp = qp0; }

                            break;
                        case "setheader":
                        case "header":
                        case "h":
                            SetHeaderParams sp0 = new SetHeaderParams();

                            if (n2["name"] == null) throw new Exception(); // must be present
                            sp0.Header = n2["name"].Value;

                            if (n2["value"] != null)
                            {
                                sp0.Value = n2["value"].Value;
                                if (n2["value"].Attributes["append"] != null && AgentBase._is_true(n2["value"].Attributes["append"])) sp0.Append = true;
                            };

                            if (bb == 1) { u = ResponseAction.SetHeader; up = sp0; }
                            else if (bb == 2) { p = ResponseAction.SetHeader; pp = sp0; }
                            else if (bb == 3) { f = ResponseAction.SetHeader; fp = sp0; }

                            break;
                        case "modifyscl":
                        case "scl":
                        case "s":
                            ModifySCLParams mp0 = new ModifySCLParams();
                            int v;

                            if (n2["absolute"] != null)
                            {
                                if (!int.TryParse(n2["absolute"].InnerText, out v)) throw new Exception();
                                mp0.Modifier = (short)v;
                                mp0.IsRelative = false;

                                if (bb == 1) { u = ResponseAction.ModifySCL; up = mp0; }
                                else if (bb == 2) { p = ResponseAction.ModifySCL; pp = mp0; }
                                else if (bb == 3) { f = ResponseAction.ModifySCL; fp = mp0; };

                                break; // first encounter wins
                            }
                            else if (n2["relative"] != null)
                            {
                                if (!int.TryParse(n2["relative"].InnerText, out v)) throw new Exception();
                                mp0.Modifier = (short)v;
                                mp0.IsRelative = true;

                                if (bb == 1) { u = ResponseAction.ModifySCL; up = mp0; }
                                else if (bb == 2) { p = ResponseAction.ModifySCL; pp = mp0; }
                                else if (bb == 3) { f = ResponseAction.ModifySCL; fp = mp0; };

                                break; // first encounter wins
                            }
                            else continue; // unrecognized
                        default: continue; // unrecognized
                    };
                };
            };
        }

        private bool _load_cfg()
        {
            string sb1; int nb; byte bb = 0;   

            try
            {
                XmlDocument cfg = AgentBase.Configuration;

                foreach (XmlNode n0 in cfg.ChildNodes) // root element
                {
                    foreach (XmlNode n1 in n0.ChildNodes)
                    {
                        if (n1.NodeType == XmlNodeType.Element && n1.Name.ToLower() == "arclight.verifier")
                        {
                            if (n1.Attributes.Count > 0)
                            {
                                foreach (XmlAttribute n1a in n1.Attributes)
                                { // TODO ELSE IF
                                    if (n1a.Name.ToLower() == "enabled" && !AgentBase._is_true(n1a)) return false; // must be enabled
                                    else if (n1a.Name.ToLower() == "debug" && AgentBase._is_true(n1a)) _debug = true;
                                    else if (n1a.Name.ToLower() == "ar" && AgentBase._is_true(n1a)) _ar_header = true;
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
                                    }
                                    else if (n1a.Name.ToLower() == "stats" && AgentBase._is_true(n1a)) _stats = true;
                                };
                            };

                            // verifier section
                            foreach (XmlNode n2 in n1.ChildNodes)
                            {
                                if (n2.NodeType == XmlNodeType.Element && (n2.Name.ToLower() == "defaults" || n2.Name.ToLower() == "default"))
                                {
                                    if ((bb & 0x01) == 0x01) continue; // already set

                                    XmlNode n2copy = n2;

                                    try
                                    {
                                        _cfg_read_domain_section(ref n2copy, ref _default_unsig_act, ref _default_pass_act, ref _default_fail_act,
                                                ref _default_unsig_params, ref _default_pass_params, ref _default_fail_params);

                                        bb = (byte)(bb | 0x01);
                                    }
                                    catch { continue; }; // section invalid
                                }
                                else if (n2.NodeType == XmlNodeType.Element && (n2.Name.ToLower() == "domains" || n2.Name.ToLower() == "domain"))
                                {
                                    foreach (XmlNode n3 in n2.ChildNodes)
                                    {
                                        if (_dom_key != null && Array.BinarySearch<string>(_dom_key, n3.Value.ToLower().Trim()) >= 0) continue; // first occurence wins
                                        else
                                        {
                                            ResponseAction ua = new ResponseAction(), pa = new ResponseAction(), fa = new ResponseAction();
                                            ActionParams uap = null, pap = null, fap = null;

                                            XmlNode n3copy = n3;

                                            try
                                            {
                                                _cfg_read_domain_section(ref n3copy, ref ua, ref pa, ref fa, ref uap, ref pap, ref fap);

                                                nb = _dom_key == null ? 0 : _dom_key.Length;

                                                Array.Resize<string>(ref _dom_key, nb + 1); _dom_key[nb] = n3.Value.ToLower().Trim();
                                                Array.Resize<int>(ref _dom_ord, _dom_key.Length); _dom_ord[nb] = nb;

                                                Array.Resize<ResponseAction>(ref _dom_unsig_act, _dom_key.Length); _dom_unsig_act[nb] = ua;
                                                Array.Resize<ResponseAction>(ref _dom_pass_act, _dom_key.Length); _dom_pass_act[nb] = pa;
                                                Array.Resize<ResponseAction>(ref _dom_fail_act, _dom_key.Length); _dom_fail_act[nb] = fa;
                                                Array.Resize<ActionParams>(ref _dom_unsig_params, _dom_key.Length); _dom_unsig_params[nb] = uap;
                                                Array.Resize<ActionParams>(ref _dom_pass_params, _dom_key.Length); _dom_pass_params[nb] = pap;
                                                Array.Resize<ActionParams>(ref _dom_fail_params, _dom_key.Length); _dom_fail_params[nb] = fap;

                                                Array.Sort(_dom_key, _dom_ord);

                                                bb = (byte)(bb | 0x02); // at least one domain section loaded
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
    }
}