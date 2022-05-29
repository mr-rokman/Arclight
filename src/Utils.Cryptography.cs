using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace Arclight
{
    namespace Utils
    {
        namespace Cryptography
        {
            public static class RSA
            {
                public static RSAParameters GenerateKeypair(int KeysizeBits) // can be slow as hell TODO cross-platform this shit
                {
                    RSACryptoServiceProvider kp; RSAParameters rv;

                    if (KeysizeBits <= 0) throw new ArgumentOutOfRangeException();

                    kp = new RSACryptoServiceProvider(KeysizeBits);

                    try
                    {
                        rv = kp.ExportParameters(true);

                        kp.PersistKeyInCsp = false;

                        kp.Clear();

                        return rv;
                    }
                    finally
                    {
                        try
                        {
                            kp.PersistKeyInCsp = false;
                            kp.Clear();
                        }
                        catch { };
                    };
                }

                public static byte[] ParamsToAsn1Der(RSAParameters Params, bool IncludePrivate)
                {
                    if (IncludePrivate)
                    {
                        ASN1.Sequence rv = new ASN1.Sequence();

                        rv.Items.Add(new ASN1.Integer(new byte[1] { 0 }, +1)); // version
                        rv.Items.Add(new ASN1.Integer(Params.Modulus, +1)); // rsa modulus
                        rv.Items.Add(new ASN1.Integer(Params.Exponent, +1)); // rsa public exponent
                        rv.Items.Add(new ASN1.Integer(Params.D, +1)); // rsa private exponent
                        rv.Items.Add(new ASN1.Integer(Params.P, +1)); // rsa prime1
                        rv.Items.Add(new ASN1.Integer(Params.Q, +1)); // rsa prime2
                        rv.Items.Add(new ASN1.Integer(Params.DP, +1)); // rsa exponent1
                        rv.Items.Add(new ASN1.Integer(Params.DQ, +1)); // rsa exponent2
                        rv.Items.Add(new ASN1.Integer(Params.InverseQ, +1)); // rsa coefficient

                        return ASN1.SerializeDER(rv);
                    }
                    else
                    {
                        ASN1.Sequence rv = new ASN1.Sequence();
                        rv.Items.Add(new ASN1.Sequence(new ASN1.OID("1.2.840.113549.1.1.1"), new ASN1.Null())); // rsa oid + null
                        rv.Items.Add(new ASN1.BitString(new ASN1.Sequence(new ASN1.Integer(Params.Modulus, +1), new ASN1.Integer(Params.Exponent, +1)))); // rsa modulus + rsa public exponent

                        return ASN1.SerializeDER(rv);
                    };
                }

                public static string ParamsToBase64(RSAParameters Params, bool IncludePrivate) { return ParamsToBase64(Params, IncludePrivate, false); }
                public static string ParamsToBase64(RSAParameters Params, bool IncludePrivate, bool PemDecorations)
                {
                    const int alignment = 64; // хз стандартно ли это

                    StringBuilder rv; byte[] der; string bstr; int i;

                    der = RSA.ParamsToAsn1Der(Params, IncludePrivate);
                    rv = new StringBuilder((int)(der.Length * 1.25)); // estimate

                    if (PemDecorations)
                    {
                        if (IncludePrivate) rv.Append("-----BEGIN RSA PRIVATE KEY-----\r\n");
                        else rv.Append("-----BEGIN PUBLIC KEY-----\r\n");
                    };

                    bstr = Convert.ToBase64String(der);

                    if (PemDecorations)
                    {
                        i = 0;
                        while (true)
                        {
                            if (bstr.Length - i >= alignment)
                            {
                                rv.Append(bstr.Substring(i, alignment));
                                if (bstr.Length - i > alignment) rv.Append("\r\n");

                                i += alignment;
                            }
                            else if (bstr.Length - i <= 0) break;
                            else
                            {
                                rv.Append(bstr.Substring(i, bstr.Length - i)); i += alignment;
                            };
                        };
                    }
                    else rv.Append(bstr);

                    if (PemDecorations)
                    {
                        if (IncludePrivate) rv.Append("\r\n-----END RSA PRIVATE KEY-----");
                        else rv.Append("\r\n-----END PUBLIC KEY-----");
                    };

                    return rv.ToString();
                }

                public static RSAParameters Asn1DerToParams(byte[] Data)
                {
                    RSAParameters rv;
                    ASN1.Item iv;

                    try
                    {
                        iv = ASN1.DeserializeDER(Data, true);

                        rv = new RSAParameters();

                        if (iv.GetType() != typeof(ASN1.Sequence)) throw new FormatException("Unrecognized data");

                        if (iv.Items[0].GetType() == typeof(ASN1.Integer) && ((ASN1.Integer)iv.Items[0]).IsZero) // assume private struct
                        {
                            rv.Modulus = ((ASN1.Integer)iv.Items[1]).GetValue();
                            rv.Exponent = ((ASN1.Integer)iv.Items[2]).GetValue();
                            rv.D = ((ASN1.Integer)iv.Items[3]).GetValue();
                            rv.P = ((ASN1.Integer)iv.Items[4]).GetValue();
                            rv.Q = ((ASN1.Integer)iv.Items[5]).GetValue();
                            rv.DP = ((ASN1.Integer)iv.Items[6]).GetValue();
                            rv.DQ = ((ASN1.Integer)iv.Items[7]).GetValue();
                            rv.InverseQ = ((ASN1.Integer)iv.Items[8]).GetValue();
                        }
                        else if (iv.Items[0].GetType() == typeof(ASN1.Sequence) && iv.Items[0].Items[0].GetType() == typeof(ASN1.OID) && ((ASN1.OID)iv.Items[0].Items[0]).ToString() == "1.2.840.113549.1.1.1") // assume public struct
                        {
                            rv.Modulus = ((ASN1.Integer)iv.Items[1].Items[0].Items[0]).GetValue();
                            rv.Exponent = ((ASN1.Integer)iv.Items[1].Items[0].Items[1]).GetValue();
                        }
                        else throw new FormatException("Unrecognized data");

                        return rv;
                    }
                    catch (Exception e) { throw e.InnerException; }
                }

                public static RSAParameters Base64ToParams(string Data)
                {
                    string ln;
                    StringBuilder sb = new StringBuilder((int)(Data.Length * 0.75));

                    using (StreamReader sr = new StreamReader(new MemoryStream(System.Text.Encoding.ASCII.GetBytes(Data)), ASCIIEncoding.ASCII))
                    {
                        while (!sr.EndOfStream)
                        {
                            ln = sr.ReadLine();
                            if (ln.Substring(0, 1)[0] == '-') continue; // pem decoration, ignore
                            if (ln.IndexOf(':') >= 0) continue; // possible pgp decorations, ignore
                            else sb.Append(ln);
                        };
                    };

                    return Asn1DerToParams(System.Convert.FromBase64String(sb.ToString()));
                }
            }
        }
    }
}