using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Numerics;
using System.Security.Cryptography;
using System.Text;
using BaseConverter;
using Mycelo.Parsecs;

namespace bignumber
{
    class Program
    {
        static void Main(string[] args)
        {
            ParsecsParser parser = new ParsecsParser();
            var padding = parser.AddString('p', "padding", 1, 1, "minimum length of displayed result");
            parser.AddOption('?', "help", null);

            var parser_base = parser.AddChoice('h', "base of result (DEFAULT: hexadecimal)");
            parser_base.AddItem('b', "bin", "binary base (2)");
            parser_base.AddItem('o', "oct", "octal base (8)");
            parser_base.AddItem('d', "dec", "decimal base (10)");
            parser_base.AddItem('h', "hex", "hexadecimal base (16)");
            parser_base.AddItem(default, "b32", "base 32 (A..Z, 2..7)");
            parser_base.AddItem(default, "b36", "base 36 (A..Z, 0-9)");
            parser_base.AddItem(default, "b64", "base 64 (A..Z, a..z, 0-9, +, /, =)");

            var parser_disp = parser.AddCommand("disp", "convert base and/or hash of A");
            var parser_add = parser.AddCommand("add", "sum of A and B");
            var parser_sub = parser.AddCommand("sub", "subtract B from A");
            var parser_mul = parser.AddCommand("mul", "multiply A and B");
            var parser_div = parser.AddCommand("div", "divide A by B");
            var parser_pow = parser.AddCommand("pow", "power of A over B");
            var parser_or = parser.AddCommand("or", "binary OR between A and B");
            var parser_and = parser.AddCommand("and", "binary AND between A and B");
            var parser_xor = parser.AddCommand("xor", "binary XOR between A and B");
            var parser_e1des = parser.AddCommand("e1des", "encrypt A with key B, DES algorithm");
            var parser_d1des = parser.AddCommand("d1des", "decrypt A wity key B, DES algorithm");
            var parser_e3des = parser.AddCommand("e3des", "encrypt A with key B, 3-DES/2-key algorithm");
            var parser_d3des = parser.AddCommand("d3des", "decrypt A with key B, 3-DES/2-key algorithm");

            foreach (var command in new ParsecsCommand[] { parser_disp, parser_add, parser_sub, parser_mul, parser_div, parser_pow, parser_or, parser_and, parser_xor, parser_e1des, parser_d1des, parser_e3des, parser_d3des })
            {
                var operand_base = command.AddChoice('h', "base of operand(s) (DEFAULT: hexadecimal)");
                operand_base.AddItem('b', "bin", "binary base (2)");
                operand_base.AddItem('o', "oct", "octal base (8)");
                operand_base.AddItem('d', "dec", "decimal base (10)");
                operand_base.AddItem('h', "hex", "hexadecimal base (16)");
                operand_base.AddItem(default, "b32", "base 32 (A..Z, 2..7)");
                operand_base.AddItem(default, "b36", "base 36 (A..Z, 0-9)");
                operand_base.AddItem(default, "b64", "base 64 (A..Z, a..z, 0-9, +, /, =)");
                command.AddOption('?', "help", null);
            }

            var parser_show_alg = parser_disp.AddChoice('0', "hash algorithm");
            parser_show_alg.AddItem('0', null, null);
            parser_show_alg.AddItem('1', "md5", "MD5");
            parser_show_alg.AddItem('2', "sha1", "SHA-1");
            parser_show_alg.AddItem('3', "sha256", "SHA-256");
            parser_show_alg.AddItem('4', "sha384", "SHA-384");
            parser_show_alg.AddItem('5', "sha512", "SHA-512");

            foreach (var command in new ParsecsCommand[] { parser_e1des, parser_d1des, parser_e3des, parser_d3des })
            {
                var cipher_mode = command.AddChoice('e', "cipher mode");
                cipher_mode.AddItem('c', "cbc", "CBC (Cipher Block Chaining)");
                cipher_mode.AddItem('e', "ecb", "ECB (Electronic Codebook)");
            }

            if (parser.Parse(args))
            {
                if ((args.Length == 0) || parser['?'])
                {
                    Console.WriteLine("BIGNUMBER [<main-options>] <operator> (--help|<operator-options>)");
                    Console.WriteLine();
                    Console.WriteLine(parser.HelpTextBuilder(4, false).ToString());
                    Console.WriteLine();
                    Console.WriteLine("Examples:");
                    Console.WriteLine("     Convert binary to hexadecimal");
                    Console.WriteLine("             BIGNUMBER --hex disp --bin 10101010");
                    Console.WriteLine("     Convert hexadecimal to binary");
                    Console.WriteLine("             BIGNUMBER --bin disp --hex AA");
                    Console.WriteLine("     XOR between two binary values");
                    Console.WriteLine("             BIGNUMBER --bin xor --bin 11110000 00001111");
                    Console.WriteLine("     Encrypt two hexadecimal values with DES algorithm");
                    Console.WriteLine("             BIGNUMBER --hex e1des --hex 0000000000000000 0123456789ABCDEF");
                    Console.WriteLine("     SHA-256 hash of an hexadecimal value displayed in padded binary");
                    Console.WriteLine("             BIGNUMBER --bin --padding=256 disp --sha256 --hex F0F0F0F0F0F0F0F0");
                }
                else if (parser.Command != parser)
                {
                    ParsecsCommand command = parser.Command;

                    if (command['?'])
                    {
                        Console.WriteLine($"BIGNUMBER {command.Name} [<operator-options>] <operand-A> [<operand-B>]");
                        Console.WriteLine();
                        Console.WriteLine(command.HelpTextBuilder(4, false).ToString());
                    }
                    else
                    {
                        try
                        {
                            int base_result = BaseFromParam(parser);
                            int base_operand = BaseFromParam(command);
                            int pad_result = 1;
                            string number1 = command.LooseParameters.FirstOrDefault();
                            string number2 = command.LooseParameters.Skip(1).FirstOrDefault();

                            if (parser['p'])
                            {
                                if (!Int32.TryParse(padding.String, out pad_result))
                                {
                                    pad_result = 1;
                                }
                            }

                            Console.WriteLine(ConfigOperator(command, base_result, pad_result, ParseNumber(number1, base_operand), ParseNumber(number2, base_operand)));
                        }
                        catch (Exception e)
                        {
                            Console.WriteLine(e.Message);
                        }
                    }
                }
                else
                {
                    Console.WriteLine("operator not specified");
                    Environment.Exit(-1);
                }
            }
            else
            {
                Console.WriteLine("wrong parameter");
                Environment.Exit(-1);
            }
        }

        static string ConfigOperator(ParsecsCommand command, int base_result, int pad_result, BigInteger number1, BigInteger number2)
        {
            HashEnum hash_enum = HashEnum.nil;
            CipherMode cipher_mode = CipherMode.ECB;
            BigInteger result;

            if (command['e'])
            {
                cipher_mode = CipherMode.CBC;
            }

            if (command['1'])
            {
                hash_enum = HashEnum.md5;
            }
            else if (command['2'])
            {
                hash_enum = HashEnum.sha1;
            }
            else if (command['3'])
            {
                hash_enum = HashEnum.sha256;
            }
            else if (command['4'])
            {
                hash_enum = HashEnum.sha384;
            }
            else if (command['5'])
            {
                hash_enum = HashEnum.sha512;
            }

            result = ApplyOperator(command.Name, number1, number2, hash_enum, cipher_mode);
            return BigIntToBase(result, base_result, pad_result);
        }

        static BigInteger ParseNumber(string p_number_string, int p_number_base)
        {
            StringBuilder number = new StringBuilder(p_number_string);
            int number_base = p_number_base;
            BigInteger bi;

            if (String.IsNullOrWhiteSpace(p_number_string))
            {
                bi = 0;
            }
            else if (number_base == 10)
            {
                bi = BigInteger.Parse(p_number_string);
            }
            else
            {
                List<Byte> byte_array = new List<byte>();

                AnyBaseConverter<StringBuilder, List<Byte>> str_to_array = new AnyBaseConverter<StringBuilder, List<byte>>(
                    source_base: number_base,
                    target_base: 0x100,
                    source_finished: (string_builder) =>
                        {
                            return string_builder.Length == 0;
                        },
                    get_next_source_digit: (string_builder) =>
                        {
                            char digit = string_builder[string_builder.Length - 1];
                            string_builder.Remove(string_builder.Length - 1, 1);
                            return BaseMap.GetValue(digit, number_base);
                        },
                    put_next_target_digit: (byte_list, digit) =>
                        {
                            byte_list.Add((Byte)digit);
                        });

                str_to_array.Convert(number, byte_array);
                bi = new BigInteger(byte_array.ToArray());
            }

            return bi;
        }

        static string BigIntToBase(BigInteger biginteger, int base_result, int pad_result)
        {
            if (base_result == 10)
            {
                return biginteger.ToString().PadLeft(pad_result, '0');
            }
            else
            {
                StringBuilder result = new StringBuilder();
                List<Byte> byte_list = new List<byte>(biginteger.ToByteArray());

                AnyBaseConverter<List<Byte>, StringBuilder> str_to_array = new AnyBaseConverter<List<byte>, StringBuilder>(
                    source_base: 0x100,
                    target_base: base_result,
                    source_finished: (byte_array) =>
                    {
                        return byte_array.Count == 0;
                    },
                    get_next_source_digit: (byte_array) =>
                    {
                        byte digit = byte_list[0];
                        byte_list.RemoveAt(0);
                        return (Int32)digit;
                    },
                    put_next_target_digit: (string_builder, digit) =>
                    {
                        string_builder.Insert(0, BaseMap.GetDigit(digit, base_result));
                    });

                str_to_array.Convert(byte_list, result);

                while ((result.Length >= Math.Max(1, pad_result)) && (result[0] == BaseMap.GetDigit(0, base_result) && (result.Length > pad_result))) { result.Remove(0, 1); }
                return result.ToString().PadLeft(pad_result, BaseMap.GetDigit(0, base_result));
            }
        }

        static BigInteger ApplyOperator(string operation, BigInteger number1, BigInteger number2, HashEnum hash_enum, CipherMode cipher_mode)
        {
            BigInteger result = new BigInteger(0);

            switch (operation)
            {
                case "disp":
                    if (hash_enum == HashEnum.nil)
                    {
                        result = number1;
                    }
                    else
                    {
                        result = MakeHash(hash_enum, number1);
                    }
                    break;

                case "add":
                    result = number1 + number2;
                    break;

                case "sub":
                    result = BigInteger.Abs(number1 - number2);
                    break;

                case "mul":
                    result = number1 * number2;
                    break;

                case "div":
                    result = number1 / number2;
                    break;

                case "pow":
                    result = BigInteger.Pow(number1, (Int32)number2);
                    break;

                case "or":
                    result = number1 | number2;
                    break;

                case "and":
                    result = number1 & number2;
                    break;

                case "xor":
                    result = number1 ^ number2;
                    break;

                case "e1des":
                    result = DESCipher(new DESCryptoServiceProvider(), cipher_mode, 8, number1, number2);
                    break;

                case "e3des":
                    result = DESCipher(new TripleDESCryptoServiceProvider(), cipher_mode, 16, number1, number2);
                    break;

                case "d1des":
                    result = DESDecipher(new DESCryptoServiceProvider(), cipher_mode, 8, number1, number2);
                    break;

                case "d3des":
                    result = DESDecipher(new TripleDESCryptoServiceProvider(), cipher_mode, 16, number1, number2);
                    break;
            }

            return result;
        }

        static BigInteger MakeHash(HashEnum hash_enum, BigInteger input)
        {
            HashAlgorithm hash_alg = null;

            switch (hash_enum)
            {
                case HashEnum.md5:
                    hash_alg = MD5.Create();
                    break;
                case HashEnum.sha1:
                    hash_alg = SHA1.Create();
                    break;
                case HashEnum.sha256:
                    hash_alg = SHA256.Create();
                    break;
                case HashEnum.sha384:
                    hash_alg = SHA384.Create();
                    break;
                case HashEnum.sha512:
                    hash_alg = SHA512.Create();
                    break;
            }

            byte[] v_input = BigIntToByteArray(input);
            byte[] v_hashed = hash_alg.ComputeHash(v_input);
            return ByteArrayToBigInt(v_hashed);
        }

        static BigInteger DESCipher(SymmetricAlgorithm p_des_alg, CipherMode p_ecm, int p_keysize, BigInteger p_input, BigInteger p_key)
        {
            p_des_alg.KeySize = p_keysize * 8;
            p_des_alg.BlockSize = 64;
            p_des_alg.Mode = p_ecm;
            p_des_alg.Padding = PaddingMode.Zeros;

            byte[] v_iv = Enumerable.Repeat<byte>(0, p_keysize).ToArray();

            byte[] v_bi_key = BigIntToByteArray(p_key, p_keysize);
            byte[] v_bi_plain = BigIntToByteArray(p_input, 8);

            using (MemoryStream msEncrypt = new MemoryStream())
            {
                using (CryptoStream csEncrypt = new CryptoStream(msEncrypt, p_des_alg.CreateEncryptor(v_bi_key, v_iv), CryptoStreamMode.Write))
                {
                    using (BinaryWriter swEncrypt = new BinaryWriter(csEncrypt))
                    {
                        swEncrypt.Write(v_bi_plain);
                    }
                }

                return ByteArrayToBigInt(msEncrypt.ToArray());
            }
        }

        static BigInteger DESDecipher(SymmetricAlgorithm p_des_alg, CipherMode p_ecm, int p_keysize, BigInteger p_input, BigInteger p_key)
        {
            p_des_alg.KeySize = p_keysize * 8;
            p_des_alg.BlockSize = 64;
            p_des_alg.Mode = p_ecm;
            p_des_alg.Padding = PaddingMode.Zeros;

            byte[] v_iv = Enumerable.Repeat<byte>(0, p_keysize).ToArray();

            byte[] v_bi_key = BigIntToByteArray(p_key, p_keysize);
            byte[] v_bi_crypt = BigIntToByteArray(p_input, 8);

            using (MemoryStream msEncrypt = new MemoryStream(v_bi_crypt))
            {
                using (CryptoStream csEncrypt = new CryptoStream(msEncrypt, p_des_alg.CreateDecryptor(v_bi_key, v_iv), CryptoStreamMode.Read))
                {
                    using (BinaryReader swEncrypt = new BinaryReader(csEncrypt))
                    {
                        return ByteArrayToBigInt(swEncrypt.ReadBytes(v_bi_crypt.Length));
                    }
                }
            }
        }

        static byte[] BigIntToByteArray(BigInteger p_bigint, int p_padding = 0)
        {
            byte[] v_reverse = p_bigint.ToByteArray();
            Array.Reverse(v_reverse);
            List<Byte> v_list = new List<byte>(v_reverse);
            if (v_list[0] == 0) { v_list.RemoveAt(0); }
            while (v_list.Count < p_padding) { v_list.Insert(0, 0); }
            return v_list.ToArray();
        }

        static BigInteger ByteArrayToBigInt(byte[] p_array)
        {
            List<Byte> v_list = new List<byte>(p_array);
            if (v_list[0] != 0) { v_list.Insert(0, 0); }
            Byte[] v_reverse = v_list.ToArray();
            Array.Reverse(v_reverse);
            return new BigInteger(v_reverse);
        }

        static int BaseFromParam(ParsecsCommand command)
        {
            int base_result;

            if (command['b'])
            {
                base_result = 2;
            }
            else if (command['o'])
            {
                base_result = 8;
            }
            else if (command['d'])
            {
                base_result = 10;
            }
            else if (command['h'])
            {
                base_result = 16;
            }
            else if (command["b32"])
            {
                base_result = 32;
            }
            else if (command["b36"])
            {
                base_result = 36;
            }
            else if (command["b64"])
            {
                base_result = 64;
            }
            else
            {
                base_result = 16;
            }

            return base_result;
        }

        enum HashEnum
        {
            nil,
            md5,
            sha1,
            sha256,
            sha384,
            sha512
        }
    }
}
