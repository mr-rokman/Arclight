using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace Arclight
{
    namespace Utils
    {
        public static class ASN1 // imcomplete, good enough for rsa keys
        {
            public abstract class Item
            {
                protected byte[] data;
                protected List<Item> items;

                public virtual List<Item> Items { get; set; }
                public abstract ulong Length { get; }
            }

            public class Integer : Item // kinda incomplete as it needs apm from net4
            {
                protected sbyte sgn;

                public void SetValue(byte[] RawData, sbyte Sign)
                {
                    if (RawData == null || RawData.Length == 0)
                    {
                        data = null;
                        sgn = 0;
                    }
                    else
                    {
                        data = new byte[RawData.Length];
                        Array.Copy(RawData, 0, data, 0, data.Length);
                        sgn = (sbyte)(Sign >= 0 ? (Sign == 0 ? 0 : +1) : -1);
                    };
                }
                public byte[] GetValue()
                {
                    if (data == null || data.Length == 0) return null;
                    else
                    {
                        byte[] rv = new byte[data.Length];
                        Array.Copy(data, 0, rv, 0, rv.Length);

                        return rv;
                    };
                }

                public Integer() { }
                public Integer(byte[] RawData) : this(RawData, +1) { }
                public Integer(byte[] RawData, sbyte Sign)
                {
                    SetValue(RawData, Sign);
                }

                public bool IsNegative { get { if (sgn < 0) return true; else return false; } }
                public bool IsZero
                {
                    get
                    {
                        if (data == null || data.Length == 0) return true;
                        else
                        {
                            for (int i = 0; i < data.Length; ++i) if (data[i] != 0x00) return false;

                            return true;
                        }
                    }
                }

                public override ulong Length { get { return (ulong)(data != null ? 0 : data.Length); } }

                protected new List<Item> Items { get { return null; } } // типа заглушка
            }

            public class BitString : Item
            {
                protected byte ub;
                public int UnusedBits
                {
                    get { return ub; }
                    set { ub = (byte)(value % 8); } // MAYBE throw if > 8 ?
                }

                public override ulong Length
                {
                    get
                    {
                        return (ulong)(data != null ? data.Length : 0);
                    }
                }

                public byte[] Data
                {
                    get
                    {
                        if (items != null && items.Count > 0) // no raw data, use Items
                        {
                            if (data != null || data.Length > 0) data = null; // stabilize

                            return null;
                        }
                        else return data;
                    }
                    set // tricky
                    {
                        if (items != null && items.Count > 0 && value != null && value.Length > 0) // switch from structured to raw
                        {
                            items.Clear();

                            data = new byte[Data.Length];
                            Array.Copy(value, 0, data, 0, data.Length);
                        }
                        else if (value == null || value.Length == 0) // erase all data
                        {
                            data = null;
                        }
                    }
                }

                public override List<Item> Items
                {
                    get { if (items == null) items = new List<Item>(); return items; }
                    set // tricky one
                    {
                        if ((items != null || items.Count == 0) && value != null && value.Count > 0) // switch from raw to structured
                        {
                            data = null; // bye bye
                            items = value;
                        }
                        else if (items != null && items.Count > 0 && (value == null || value.Count == 0)) // erase all data
                        {
                            items.Clear();
                        }
                    }
                }

                public bool IsStructured { get { if ((data == null || data.Length == 0) && items != null && items.Count > 0) return true; else return false; } }
                public bool IsRaw { get { if ((data != null && data.Length > 0) && (items == null || items.Count == 0)) return true; else return false; } }

                public BitString() { ub = 0; }
                public BitString(byte[] Data) : this(Data, 0) { }
                public BitString(byte[] Data, byte UnusedBits)
                {
                    ub = 0;
                    if (Data == null || Data.Length == 0) return;

                    data = new byte[Data.Length];
                    Array.Copy(Data, 0, data, 0, data.Length);
                }
                public BitString(Item SubItem) { items = new List<Item>(); items.Add(SubItem); }
                //public BitString(Item[] SubItems) { items = new List<Item>(); for (int i = 0; i < SubItems.Length; ++i) items.Add(SubItems[i]); }
                public BitString(List<Item> SubItems) { items = new List<Item>(SubItems); }
                public BitString(params Item[] SubItems) { items = new List<Item>(); for (int i = 0; i < SubItems.Length; ++i) items.Add(SubItems[i]); }
            }

            public class OID : Item
            {
                protected new ulong[] data;

                public static OID FromString(string OIDString) { return new OID(OIDString); }

                public override ulong Length { get { return (data == null || data.Length == 0 ? 0 : (ulong)data.Length); } }

                public ulong this[uint Position]
                {
                    get
                    {
                        if (Position > this.Length) return 0;
                        else return data[Position - 1];
                    }
                    set
                    {
                        if (Position > this.Length)
                        {
                            ulong s1 = this.Length - 1;
                            Array.Resize<ulong>(ref data, (int)Position);
                        };

                        data[Position - 1] = value;
                    }
                }

                public OID() { }
                public OID(string OIDString)
                {
                    string[] toks; ulong[] tokn; int i;

                    if (OIDString == null || OIDString.Length == 0) return;

                    toks = OIDString.Split('.');

                    if (toks.Length == 0) return;
                    else
                    {
                        tokn = new ulong[toks.Length];
                        for (i = 0; i < toks.Length; ++i) { tokn[i] = uint.Parse(toks[i]); };

                        if ((tokn.Length >= 1 && tokn[0] > 2) || (tokn.Length >= 2 && tokn[1] > 39)) throw new ArgumentOutOfRangeException();

                        data = tokn;
                    };
                }

                public override string ToString()
                {
                    if (this.Length == 0) return new string('0', 0);
                    else
                    {
                        string rv = new string('0', 0);

                        for (uint i = 1; i <= this.Length; ++i) { rv += (rv.Length > 0 ? '.' + this[i].ToString() : this[i].ToString()); };

                        return rv;
                    };
                }
            }

            public class Null : Item
            {
                public override ulong Length { get { return 0; } }

                private new List<Item> Items { get { return null; } } // lolwut

                public Null() { }
            }

            public class Sequence : Item
            {
                public override ulong Length { get { return (ulong)(items == null ? 0 : items.Count); } }

                public override List<Item> Items
                {
                    get { if (items == null) items = new List<Item>(); return items; }
                    set // tricky one
                    {
                        items = value;
                    }
                }

                public Sequence() { }
                public Sequence(Item Item) { items = new List<Item>(); items.Add(Item); }
                public Sequence(List<Item> SubItems) { items = new List<Item>(SubItems); }
                public Sequence(params Item[] SubItems) { items = new List<Item>(); for (int i = 0; i < SubItems.Length; ++i) items.Add(SubItems[i]); }
            }

            // TODO SET and fucking 0xA0

            private static void der_write_l(ulong l, ref byte[] dst, ref ulong dstoff)
            {
                byte[] bb; int i, j;

                if (l < 128) { dst[dstoff] = (byte)l; ++dstoff; }
                else
                {
                    j = (int)(Math.Ceiling(Math.Ceiling(Math.Log(l, 2)) / 8));
                    dst[dstoff] = (byte)(128 + j); ++dstoff;
                    bb = BitConverter.GetBytes(l); if (BitConverter.IsLittleEndian) Array.Reverse(bb);

                    for (i = bb.Length - j; i < bb.Length; ++i) { dst[dstoff] = bb[i]; ++dstoff; };
                };
            }

            private static ulong der_read_l(ref byte[] src, ref ulong srcoff)
            {
                byte[] bb; int i, j;

                i = src[srcoff]; ++srcoff;
                if (i > 127)
                {
                    i -= 128;

                    if (i > sizeof(ulong)) throw new OverflowException();
                    if (i == 0) throw new FormatException("Malformed data");

                    bb = new byte[sizeof(ulong)];
                    for (j = bb.Length - i; j < bb.Length; ++j) { bb[j] = src[srcoff]; ++srcoff; };
                    if (BitConverter.IsLittleEndian) Array.Reverse(bb);

                    return BitConverter.ToUInt64(bb, 0);
                }
                else return (ulong)i;
            }

            private static ulong der_measure_tlv(Item it, byte msk)
            {
                ulong rv = 0, rts = 0; int i;

                if (it.GetType() == typeof(ASN1.Integer))
                {
                    Integer rti = (Integer)it;
                    if (rti.IsZero) rts = 1;
                    else
                    {
                        byte[] val = rti.GetValue();

                        rts = (ulong)val.Length;
                        if (!rti.IsNegative && val[0] > 127) rts += 1; // leading 0x00 for int+
                    }
                }
                else if (it.GetType() == typeof(ASN1.BitString))
                {
                    BitString rti = (BitString)it;
                    if (rti.IsStructured) // а вообще-то по стандартам DER такая херня не допускается!
                    {
                        for (i = 0; i < rti.Items.Count; ++i) rts += der_measure_tlv(rti.Items[i], msk);
                        rts += 1; // unused bits
                    }
                    else if (rti.IsRaw) { rts = 1 + rti.Length; }
                    else { rts += 1; };
                }
                else if (it.GetType() == typeof(ASN1.Null)) { rts = 0; }
                else if (it.GetType() == typeof(ASN1.OID))
                {
                    OID rti = (OID)it;
                    if (rti.Length == 0) rts = 0;
                    else if (rti.Length <= 2) rts = 1;
                    else
                    {
                        rts = 1; // first two components

                        for (i = 3; i <= (int)rti.Length; ++i)
                        {
                            rts += (rti[(uint)i] < 128 ? 1 : (ulong)Math.Ceiling(Math.Ceiling(Math.Log(rti[(uint)i], 2)) / 7));
                        };
                    };
                }
                else if (it.GetType() == typeof(ASN1.Sequence))
                {
                    Sequence rti = (Sequence)it;
                    for (i = 0; i < rti.Items.Count; ++i) rts += der_measure_tlv(rti.Items[i], msk);
                };

                if ((msk & 0x02) != 0x02)
                {
                    rts += 1; // L
                    if (rts > 127) { rts += (ulong)(Math.Ceiling(Math.Ceiling(Math.Log(rts, 2)) / 8)); } // extra L
                };

                if ((msk & 0x01) != 0x01) rts += 1; // T

                return rv + rts;
            }

            private static void der_serialize(Item it, ref byte[] dst, ref ulong dstoff)
            {
                ulong rs = 0, sts = 0; int i, j;
                byte[] bb;
                ulong nb1;

                // measure subtree size
                if (it.Items != null && it.Items.Count > 0) for (i = 0; i < it.Items.Count; ++i) sts += der_measure_tlv(it.Items[i], 0x00);

                if (it.GetType() == typeof(ASN1.Integer))
                {
                    Integer rti = (Integer)it; rs = der_measure_tlv(it, 0x03); // only V
                    dst[dstoff] = 0x02; ++dstoff; // INTEGER T
                    der_write_l(rs, ref dst, ref dstoff); // L

                    if (rti.IsZero) { dst[dstoff] = 0x00; ++dstoff; }
                    else
                    {
                        bb = rti.GetValue();

                        if (!rti.IsNegative && bb[0] > 127) { dst[dstoff] = 0x00; ++dstoff; }; // leading 0x00 for int+
                        Array.Copy(bb, 0, dst, (long)dstoff, bb.Length); dstoff += (ulong)bb.Length; // V
                    };
                }
                else if (it.GetType() == typeof(ASN1.BitString))
                {
                    BitString rti = (BitString)it;
                    if (rti.IsStructured) // а вообще-то по стандартам DER такая херня не допускается!
                    {
                        dst[dstoff] = 0x03; ++dstoff; // BITSTRING T (а вообще должно быть 0x03 + 0x20 !)
                        sts += 1; der_write_l(sts, ref dst, ref dstoff); // L
                        dst[dstoff] = 0x00; ++dstoff; // unused bits = 0

                        for (i = 0; i < rti.Items.Count; ++i) der_serialize(rti.Items[i], ref dst, ref dstoff); // V
                    }
                    else if (rti.IsRaw)
                    {
                        dst[dstoff] = 0x03; ++dstoff; // BITSTRING T
                        sts = 1 + rti.Length; der_write_l(sts, ref dst, ref dstoff); // L
                        dst[dstoff] = (byte)rti.UnusedBits; ++dstoff; // unused bits
                        Array.Copy(rti.Data, 0, dst, (long)dstoff, (int)rti.Length); dstoff += rti.Length; // V
                    }
                    else // empty
                    {
                        dst[dstoff] = 0x03; ++dstoff; // BITSTRING T
                        der_write_l(1, ref dst, ref dstoff); // L
                        dst[dstoff] = 0x00; ++dstoff; // unused bits
                        // no V
                    };
                }
                else if (it.GetType() == typeof(ASN1.Null))
                {
                    dst[dstoff] = 0x05; ++dstoff; // NULL T
                    der_write_l(0, ref dst, ref dstoff); // L
                    // no V
                }
                else if (it.GetType() == typeof(ASN1.OID))
                {
                    OID rti = (OID)it;

                    dst[dstoff] = 0x06; ++dstoff; // OID T

                    if (rti.Length == 0)
                    {
                        der_write_l(0, ref dst, ref dstoff); // L
                    }
                    else if (rti.Length == 1)
                    {
                        der_write_l(1, ref dst, ref dstoff); // L
                        dst[dstoff] = (byte)(40 * rti[1]); ++dstoff; // V
                    }
                    else
                    {
                        der_write_l(der_measure_tlv(rti, 0x01 | 0x02), ref dst, ref dstoff); // L

                        dst[dstoff] = (byte)(40 * rti[1] + rti[2]); ++dstoff; // V ...

                        if (rti.Length > 2)
                        {
                            for (i = 3; i <= (int)rti.Length; ++i) // ... V ...
                            {
                                nb1 = rti[(uint)i];

                                if (nb1 <= 127) { dst[dstoff] = (byte)nb1; ++dstoff; continue; }
                                else
                                {
                                    bb = new byte[(int)Math.Ceiling(Math.Ceiling(Math.Log(nb1, 2)) / 7)];

                                    for (j = 0; j < bb.Length; ++j) // pack component value in 7-bit chunks into buffer, reverse order
                                    {
                                        if (j == 0) bb[j] = (byte)(nb1 & 0x7F); // ender byte
                                        else bb[j] = (byte)(0x80 | (byte)(nb1 & 0x7F));
                                        nb1 = nb1 >> 7;
                                    };

                                    Array.Reverse(bb);
                                    Array.Copy(bb, 0, dst, (long)dstoff, bb.Length); dstoff += (ulong)bb.Length; // ... V
                                };
                            };
                        };
                    };
                }
                else if (it.GetType() == typeof(ASN1.Sequence))
                {
                    Sequence rti = (Sequence)it;

                    dst[dstoff] = 0x30; ++dstoff; // SEQUENCE T
                    der_write_l(sts, ref dst, ref dstoff); // L

                    for (i = 0; i < rti.Items.Count; ++i) der_serialize(rti.Items[i], ref dst, ref dstoff); // V
                };
            }

            private static Item der_deserialize(ref byte[] src, ref ulong srcoff, bool p)
            {
                Item rv = null, sit;
                byte t; ulong l;
                byte[] bb;
                ulong nb1, nb2, nb3, nb4, nb5; // assortment of numeric-buffers

                t = src[srcoff]; ++srcoff;
                l = der_read_l(ref src, ref srcoff);

                if ((ulong)src.Length - srcoff < l) throw new FormatException("Insufficient data");

                if ((t & 0x1F) == 0x02 && (t & 0x20) == 0x00) // INTEGER (!constructed)
                {
                    rv = new Integer();

                    if (l > 1 && src[srcoff] == 0x00)
                    {
                        l -= 1; ++srcoff;
                        bb = new byte[l];
                        Array.Copy(src, (int)srcoff, bb, 0, bb.Length); srcoff += (ulong)bb.Length;
                        ((Integer)rv).SetValue(bb, +1);
                    }
                    else if (src[srcoff] > 127)
                    {
                        bb = new byte[l];
                        Array.Copy(src, (int)srcoff, bb, 0, bb.Length); srcoff += (ulong)bb.Length;
                        ((Integer)rv).SetValue(bb, -1);
                    }
                    else if (l > 0)
                    {
                        bb = new byte[l];
                        Array.Copy(src, (int)srcoff, bb, 0, bb.Length); srcoff += (ulong)bb.Length;
                        ((Integer)rv).SetValue(bb, +1);
                    };
                }
                else if ((t & 0x1F) == 0x03) // BITSTRING
                {
                    nb1 = src[srcoff]; ++srcoff; --l; // unused bits

                    if (l > 0 && (t & 0x20) == 0x20) // CONSTRUCTED
                    {
                        rv = new BitString();
                        nb2 = srcoff; // starter
                        while (srcoff < nb2 + l)
                        {
                            sit = der_deserialize(ref src, ref srcoff, p);
                            ((BitString)rv).Items.Add(sit);
                        };
                    }
                    else if (l > 0 && (t & 0x20) != 0x20) // PRIMITIVE (but who knows for real...)
                    {
                        if (!p) // treat as raw
                        {
                            bb = new byte[l];
                            Array.Copy(src, (long)srcoff, bb, 0, bb.Length); srcoff += (ulong)bb.Length;
                            rv = new BitString(bb, (byte)nb1);
                        }
                        else // try to deserialize
                        {
                            rv = new BitString();
                            nb2 = srcoff; // starter
                            try
                            {
                                while (srcoff < nb2 + l)
                                {
                                    sit = der_deserialize(ref src, ref srcoff, p);
                                    ((BitString)rv).Items.Add(sit);
                                };
                            }
                            catch // otherwise treat as raw
                            {
                                srcoff = nb1; // rewind

                                bb = new byte[l];
                                Array.Copy(src, (long)srcoff, bb, 0, bb.Length); srcoff += (ulong)bb.Length;
                                rv = new BitString(bb, (byte)nb1);
                            };
                        };
                    };
                }
                else if ((t & 0x1F) == 0x05) // NULL
                {
                    if ((t & 0x20) != 0x00 || l > 0) throw new FormatException("Malformed data"); // dafuq

                    rv = new Null(); // easy
                }
                else if ((t & 0x1F) == 0x06) // OID (dunno about constructed bit) , btw deserialized oid will be at least 2 comps long
                {
                    nb1 = srcoff; // starter    

                    rv = new OID();
                    if (l == 0) return rv; // не должно быть, но кто знает

                    ((OID)rv)[1] = (ulong)(Math.Floor((double)src[srcoff] / 40));
                    ((OID)rv)[2] = (ulong)(src[srcoff] % 40);
                    ++srcoff;

                    if (l == 1) return rv;// oh yeah
                    else if (l > 1) // oh no
                    {
                        nb2 = 3; // component index
                        nb5 = (ulong)Math.Floor((double)(sizeof(ulong) * 8) / 7); // component byte limit (for now)

                        while (srcoff < nb1 + l)
                        {
                            nb3 = 0; // component value
                            nb4 = 0; // byte offset

                            while (true) // unpack component value in 7-bit chunks, direct order
                            {
                                if (nb4 > nb5) throw new OverflowException();
                                if (srcoff >= nb1 + l) throw new FormatException("Insufficient data");

                                if (src[srcoff] < 128) // ender
                                {
                                    nb3 = nb3 | (byte)(src[srcoff] & 0x7F);
                                    ((OID)rv)[(uint)nb2] = nb3;
                                    ++srcoff;
                                    ++nb2;
                                    break;
                                }
                                else
                                {
                                    nb3 = nb3 | (byte)(src[srcoff] & 0x7F);
                                    nb3 = nb3 << 7;
                                };

                                ++srcoff; ++nb4;
                            };
                        };
                    };
                }
                else if ((t & 0x1F) == 0x10) // SEQUENCE
                {
                    if ((t & 0x20) != 0x20) throw new FormatException("Malformed data"); // u wot m8

                    rv = new Sequence();
                    nb1 = srcoff; // starter

                    while (srcoff < nb1 + l)
                    {
                        sit = der_deserialize(ref src, ref srcoff, p);
                        ((Sequence)rv).Items.Add(sit);
                    };
                }
                else if ((t & 0x20) == 0x20) // unknown constructed
                {
                    rv = new Sequence(); // TODO new type (GenericConstructed ?)
                    nb1 = srcoff; // starter

                    while (srcoff < nb1 + l + 1)
                    {
                        sit = der_deserialize(ref src, ref srcoff, p);
                        ((Sequence)rv).Items.Add(sit);
                    };
                }
                else throw new FormatException("Unrecognized data");

                return rv;
            }

            public static byte[] SerializeDER(Item Tree)
            {
                byte[] rv; ulong rvc = 0;
                ulong rvs = der_measure_tlv(Tree, 0x00);

                if (rvs == 0) return null; // не должно быть такой фигни

                rv = new byte[rvs];

                der_serialize(Tree, ref rv, ref rvc);

                return rv;
            }

            // unpack data to new structure
            public static Item DeserializeDER(byte[] Data) { return DeserializeDER(Data, false); }

            public static Item DeserializeDER(byte[] Data, bool /* TODO поменять название! */ Tryhard)
            {
                ulong srcoff = 0;
                return der_deserialize(ref Data, ref srcoff, Tryhard);
            }

            public static string SerializeBase64(Item Tree) { return SerializeBase64(Tree, null); }

            public static string SerializeBase64(Item Tree, string DecorationCaption)
            {
                const int alignment = 64; // хз стандартно ли это
                string dc = ((DecorationCaption == null || DecorationCaption.Trim().Length == 0 ? new string('0', 0) : DecorationCaption.Trim()));

                StringBuilder rv; byte[] der; string bstr; int i;

                der = ASN1.SerializeDER(Tree);
                rv = new StringBuilder((int)(der.Length * 1.25)); // estimate

                if (dc.Length > 0)
                {
                    rv.Append("-----BEGIN ");
                    rv.Append(dc);
                    rv.Append("-----\r\n");
                };

                bstr = Convert.ToBase64String(der);

                if (dc.Length > 0)
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

                if (dc.Length > 0)
                {
                    rv.Append("-----END ");
                    rv.Append(dc);
                    rv.Append("-----\r\n");
                };

                return rv.ToString();
            }

            // kinda redundant
            public static Item DeserializeBase64(string Data)
            {
                string ln;
                StringBuilder sb = new StringBuilder((int)(Data.Length * 0.75));

                using (StreamReader sr = new StreamReader(new MemoryStream(System.Text.Encoding.ASCII.GetBytes(Data)), ASCIIEncoding.ASCII))
                {
                    while (!sr.EndOfStream)
                    {
                        ln = sr.ReadLine();
                        if (ln.Substring(0, 1)[0] == '-') continue; // pem decoration, ignore
                        else sb.Append(ln);
                    };
                };

                return ASN1.DeserializeDER(System.Convert.FromBase64String(sb.ToString()), true);
            }
            // kinda redundant
            public static Item DeserializeHexString(string Data) // probably slow as fuck but what the hell
            {
                StringBuilder sb; string str; byte[] der; byte b; int i = 0, c = 0;

                if (Data == null || Data.Length == 0) throw new ArgumentException("No data");

                sb = new StringBuilder(Data.Length);
                for (i = 0; i < Data.Length; ++i) { if (!char.IsWhiteSpace(Data[i])) sb.Append(Data[i]); };
                str = sb.ToString();

                try
                {
                    i = 0;

                    if (str.Length % 2 != 0) // assume leading zero
                    {
                        der = new byte[1 + (int)Math.Floor((double)str.Length / 2)];

                        b = byte.Parse("0" + str.Substring(0, 1), System.Globalization.NumberStyles.HexNumber);
                        der[0] = b; ++c; i = 1;
                    }
                    else der = new byte[str.Length / 2];

                    while (i < str.Length)
                    {
                        b = byte.Parse(str.Substring(i, 2), System.Globalization.NumberStyles.HexNumber); i += 2;
                        der[c] = b; ++c;
                    };

                    return DeserializeDER(der, true);
                }
                catch { throw new FormatException("Malformed data"); };
            }
        }
    }
}