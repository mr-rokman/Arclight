using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Net;
using System.Runtime.InteropServices;
using System.Text;

namespace Arclight
{
    namespace Utils
    {
        public static class Conversion
        {
            public static string ToHexString(byte[] Input) { return ToHexString(Input, false); }
            public static string ToHexString(byte[] Input, bool Uppercase)
            {
                const string abcu = "0123456789ABCDEF"; const string abcl = "0123456789abcdef";

                if (Input == null || Input.Length == 0) return string.Empty;

                StringBuilder rv = new StringBuilder(Input.Length * 2);

                for (int i = 0; i < Input.Length; ++i)
                {
                    if (Uppercase) { rv.Append(abcu[Input[i] >> 4]); rv.Append(abcu[Input[i] & 0x0F]); }
                    else { rv.Append(abcl[Input[i] >> 4]); rv.Append(abcl[Input[i] & 0x0F]); };
                };

                return rv.ToString();
            }
            public static string ToHexString(byte Input) { return ToHexString(Input, false); }
            public static string ToHexString(byte Input, bool Uppercase)
            {
                const string abcu = "0123456789ABCDEF"; const string abcl = "0123456789abcdef";

                string rv;

                    if (Uppercase) { rv = abcu.Substring(Input >> 4, 1) + abcu.Substring(Input & 0x0F, 1); }
                    else { rv = abcl.Substring(Input >> 4, 1) + abcl.Substring(Input & 0x0F, 1); };

                return rv;
            }

            public static byte[] FromHexString(string Input) // TODO optimize speed
            {
                StringBuilder sb; string str; byte[] rv; byte b; int i = 0, c = 0;

                if (Input == null || Input.Length == 0) return null;

                sb = new StringBuilder(Input.Length);
                for (i = 0; i < Input.Length; ++i) { if (!char.IsWhiteSpace(Input[i])) sb.Append(Input[i]); };
                str = sb.ToString();

                try
                {
                    i = 0;

                    if (str.Length % 2 != 0) // assume leading zero
                    {
                        rv = new byte[1 + (int)Math.Floor((double)str.Length / 2)];

                        b = byte.Parse("0" + str.Substring(0, 1), System.Globalization.NumberStyles.HexNumber);
                        rv[0] = b; ++c; i = 1;
                    }
                    else rv = new byte[str.Length / 2];

                    while (i < str.Length)
                    {
                        b = byte.Parse(str.Substring(i, 2), System.Globalization.NumberStyles.HexNumber); i += 2;
                        rv[c] = b; ++c;
                    };

                    return rv;
                }
                catch { return null; };
            }
        }
    }
}