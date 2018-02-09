using System;

namespace BaseConverter
{
    public class AnyBaseConverter<SourceType, TargetType>
        where SourceType : class
        where TargetType : class
    {
        private Func<SourceType, bool> f_source_finished;
        private Func<SourceType, int> f_get_next_source_digit;
        private Action<TargetType, int> f_put_next_target_digit;

        private int f_source_base;
        private int f_target_base;

        public AnyBaseConverter(int source_base, int target_base, Func<SourceType, bool> source_finished, Func<SourceType, int> get_next_source_digit, Action<TargetType, int> put_next_target_digit)
        {
            if (((source_base % 2) != 0) || ((target_base % 2) != 0))
            {
                throw new InvalidOperationException();
            }

            f_source_base = source_base;
            f_target_base = target_base;
            f_source_finished = source_finished;
            f_get_next_source_digit = get_next_source_digit;
            f_put_next_target_digit = put_next_target_digit;
        }

        public void Convert(SourceType source, TargetType target)
        {
            int digit_value = 0;
            int buffer = 0;
            int last_buffer = 0;
            int buffer_binary_digits = 0;
            int source_binary_digits = 0;

            int source_base_binary_digits = (Int32)Math.Floor(Math.Log(f_source_base - 1, 2)) + 1;
            int target_base_binary_digits = (Int32)Math.Floor(Math.Log(f_target_base - 1, 2)) + 1;

            while ((!f_source_finished(source)) || (source_binary_digits > 0))
            {
                while (buffer_binary_digits < target_base_binary_digits)
                {
                    if (source_binary_digits == 0)
                    {
                        if (!f_source_finished(source))
                        {
                            source_binary_digits += source_base_binary_digits;
                            digit_value = f_get_next_source_digit(source);
                        }
                        else
                        {
                            break;
                        }
                    }

                    int next_bit = digit_value % 2;
                    buffer += next_bit * (Int32)Math.Pow(2, buffer_binary_digits++);
                    digit_value /= 2;
                    source_binary_digits--;
                }

                while (buffer_binary_digits > 0)
                {
                    last_buffer = buffer % f_target_base;
                    f_put_next_target_digit(target, last_buffer);
                    buffer /= f_target_base;
                    buffer_binary_digits = Math.Max(buffer_binary_digits - target_base_binary_digits, 0);
                }
            }

            if (last_buffer != 0)
            {
                f_put_next_target_digit(target, 0);
            }
        }
    }

    public class BaseMap
    {
        public static int GetValue(char digit, int number_base)
        {
            int value;

            if ((value = Digits(number_base).IndexOf(digit)) < 0)
            {
                throw new InvalidOperationException();
            }
            else
            {
                return value;
            }
        }

        public static char GetDigit(int value, int number_base)
        {
            string digits = Digits(number_base);

            if (value >= digits.Length)
            {
                throw new InvalidOperationException();
            }
            else
            {
                return Digits(number_base)[value];
            }
        }

        private static string Digits(int number_base)
        {
            string digits;

            switch (number_base)
            {
                case 2:
                    digits = "01";
                    break;
                case 8:
                    digits = "01234567";
                    break;
                case 10:
                    digits = "01234567890";
                    break;
                case 16:
                    digits = "0123456789ABCDEF";
                    break;
                case 32:
                    digits = "ABCDEFGHIJKLMOPQRSTUVWXYZ234567";
                    break;
                case 36:
                    digits = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";
                    break;
                case 64:
                    digits = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=";
                    break;
                default:
                    throw new NotImplementedException();
            }

            return digits;
        }
    }
}
