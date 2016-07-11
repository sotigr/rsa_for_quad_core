using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace rsa_oaep
{
    class Program
    {
        /*
         This project is a resault of combining two other projects:
         OAEP by mbakkar https://github.com/mbakkar/OAEP and 
         Maciej Lis http://maciejlis.com/rsa-implementation-in-c/
         as well as additional modifications made my me while combining and
         reforming these projects. The resault is a complete RSA implementation
         with OAEP padding.
        */
        static Random random = new Random();
        static void Main(string[] args)
        {
            Console.ForegroundColor = ConsoleColor.Gray;
            Console.Title = "RSA test with OAEP (Optimal asymmetric encryption padding)";

            System.Diagnostics.Stopwatch w = new System.Diagnostics.Stopwatch();


            int p = GenerateRandomPrime((int)Math.Pow(2, 10), (int)Math.Pow(2, 12)), q = GenerateRandomPrime((int)Math.Pow(2, 12), (int)Math.Pow(2, 13));
            //int p = GenerateRandomPrime((int)Math.Pow(2, 12), (int)Math.Pow(2, 14)), q = GenerateRandomPrime((int)Math.Pow(2, 13), (int)Math.Pow(2, 16));

            uint n = (uint)(p * q);

            uint phi = (uint)((p - 1) * (q - 1));

            List<uint> possibleE = GetAllPossibleE(phi);
            uint e;
            long d;

            Console.WriteLine();
            Console.WriteLine("Generating keys...");
            Console.WriteLine();

            do
            {
                e = possibleE[random.Next(0, possibleE.Count)];
                d = ExtendedEuclidean(e % phi, phi).u1;
            } while (d < 0);


            Console.WriteLine("Public  key: ({0},{1})", n, e);
            Console.WriteLine("Private key: ({0},{1})", n, d);

            Console.WriteLine();

            Console.Write("Enter value to encode: ");
            string raw_value = Console.ReadLine();
            w.Start();
            byte[] original_value = Encoding.UTF8.GetBytes(raw_value);


            //Adding padding ot the plain text
            byte[] value = ApplyOAEP(Encoding.UTF8.GetBytes(raw_value), "SHA-256 MGF1", Encoding.UTF8.GetBytes(raw_value).Length + 32 + 32 + 1);


            Console.WriteLine();
            PrintArray("Value = ", value);


            // Encryption
            int[] encrypted_val = Encrypt(value, e, n);

            // Decryption
            byte[] decrypted_val = RemoveOAEP(Decrypt(encrypted_val, d, n), "SHA-256 MGF1");

            w.Stop();

            //Output
            Console.WriteLine();
            PrintArray("Encrypted value = ", encrypted_val);
            Console.WriteLine();
            PrintArray("Decrypted value = ", decrypted_val);
            Console.WriteLine();
            Console.WriteLine("Decrypted text = " + Encoding.UTF8.GetString(decrypted_val.ToArray()));

            Console.WriteLine();
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine("Original message is the same as the decrypted message: " + original_value.SequenceEqual(decrypted_val));
            Console.ForegroundColor = ConsoleColor.Gray;

            Console.WriteLine();
            Console.WriteLine("Completed in: " + w.ElapsedMilliseconds + "ms");

            Console.WriteLine();
            Console.WriteLine("Cipher text in Base64: " + Convert.ToBase64String(IntArrayToByteArray(encrypted_val)));
            Console.ReadKey();
        }

        static int[] Encrypt(byte[] plaintext, long e, long n)
        {
            int pt_ln = plaintext.Length;
            List<int> res = new List<int>();

            List<int> res_ts_0 = new List<int>();
            List<int> res_ts_1 = new List<int>();
            List<int> res_ts_2 = new List<int>();
            List<int> res_ts_3 = new List<int>();

            int task_share = pt_ln / 4;

            int task0_cycles = task_share;
            int task1_cycles = task_share * 2;
            int task2_cycles = task_share * 3;
            int task3_cycles = pt_ln;

            Task t0 = Task.Factory.StartNew(() =>
            {
                for (int i = 0; i < task0_cycles; i++)
                {
                    res_ts_0.Add((int)ModuloPow(Convert.ToInt32(plaintext[i]), e, n));
                }
            });
            Task t1 = Task.Factory.StartNew(() =>
            {
                for (int i = task0_cycles; i < task1_cycles; i++)
                {
                    res_ts_1.Add((int)ModuloPow(Convert.ToInt32(plaintext[i]), e, n));
                }
            });
            Task t2 = Task.Factory.StartNew(() =>
            {
                for (int i = task1_cycles; i < task2_cycles; i++)
                {
                    res_ts_2.Add((int)ModuloPow(Convert.ToInt32(plaintext[i]), e, n));
                }
            });
            Task t3 = Task.Factory.StartNew(() =>
            {
                for (int i = task2_cycles; i < task3_cycles; i++)
                {
                    res_ts_3.Add((int)ModuloPow(Convert.ToInt32(plaintext[i]), e, n));
                }
            });

            t0.Wait();
            t1.Wait();
            t2.Wait();
            t3.Wait();

            res.AddRange(res_ts_0);
            res.AddRange(res_ts_1);
            res.AddRange(res_ts_2);
            res.AddRange(res_ts_3);

            return res.ToArray();
        }

        static byte[] Decrypt(int[] plaintext, long d, long n)
        {
            int pt_ln = plaintext.Length;
            List<byte> res = new List<byte>();

            List<byte> res_ts_0 = new List<byte>();
            List<byte> res_ts_1 = new List<byte>();
            List<byte> res_ts_2 = new List<byte>();
            List<byte> res_ts_3 = new List<byte>();

            int task_share = pt_ln / 4;

            int task0_cycles = task_share;
            int task1_cycles = task_share * 2;
            int task2_cycles = task_share * 3;
            int task3_cycles = pt_ln;

            Task t0 = Task.Factory.StartNew(() =>
            {
                for (int i = 0; i < task0_cycles; i++)
                {
                    res_ts_0.Add((byte)ModuloPow(plaintext[i], d, n));
                }
            });
            Task t1 = Task.Factory.StartNew(() =>
            {
                for (int i = task0_cycles; i < task1_cycles; i++)
                {
                    res_ts_1.Add((byte)ModuloPow(plaintext[i], d, n));
                }
            });
            Task t2 = Task.Factory.StartNew(() =>
            {
                for (int i = task1_cycles; i < task2_cycles; i++)
                {
                    res_ts_2.Add((byte)ModuloPow(plaintext[i], d, n));
                }
            });
            Task t3 = Task.Factory.StartNew(() =>
            {
                for (int i = task2_cycles; i < task3_cycles; i++)
                {
                    res_ts_3.Add((byte)ModuloPow(plaintext[i], d, n));
                }
            });

            t0.Wait();
            t1.Wait();
            t2.Wait();
            t3.Wait();

            res.AddRange(res_ts_0);
            res.AddRange(res_ts_1);
            res.AddRange(res_ts_2);
            res.AddRange(res_ts_3);

            return res.ToArray();
        }

        static byte[] ApplyOAEP(byte[] message, String parameters, int length)
        {
            String[] tokens = parameters.Split(' ');
            if (tokens.Length != 2 || tokens[0] != ("SHA-256") || tokens[1] != ("MGF1"))
            {
                return null;
            }
            int mLen = message.Length;
            int hLen = 32;
            if (mLen > length - (hLen << 1) - 1)
            {
                return null;
            }
            int zeroPad = length - mLen - (hLen << 1) - 1;
            byte[] dataBlock = new byte[length - hLen];
            Array.Copy(SHA256(Encoding.UTF8.GetBytes(parameters)), 0, dataBlock, 0, hLen);
            Array.Copy(message, 0, dataBlock, hLen + zeroPad + 1, mLen);
            dataBlock[hLen + zeroPad] = 1;
            byte[] seed = new byte[hLen];
            random.NextBytes(seed);
            byte[] dataBlockMask = MGF1(seed, 0, hLen, length - hLen);
            for (int i = 0; i < length - hLen; i++)
            {
                dataBlock[i] ^= dataBlockMask[i];
            }
            byte[] seedMask = MGF1(dataBlock, 0, length - hLen, hLen);
            for (int i = 0; i < hLen; i++)
            {
                seed[i] ^= seedMask[i];
            }
            byte[] padded = new byte[length];
            Array.Copy(seed, 0, padded, 0, hLen);
            Array.Copy(dataBlock, 0, padded, hLen, length - hLen);
            return padded;
        }

        static byte[] RemoveOAEP(byte[] message, string parameters)
        {
            string[] tokens = parameters.Split(' ');
            if (tokens.Length != 2 || tokens[0] != ("SHA-256") || tokens[1] != ("MGF1"))
            {
                return null;
            }
            int mLen = message.Length;
            int hLen = 32;
            if (mLen < (hLen << 1) + 1)
            {
                return null;
            }
            byte[] copy = new byte[mLen];
            Array.Copy(message, 0, copy, 0, mLen);
            byte[] seedMask = MGF1(copy, hLen, mLen - hLen, hLen);
            for (int i = 0; i < hLen; i++)
            {
                copy[i] ^= seedMask[i];
            }
            byte[] paramsHash = SHA256(Encoding.UTF8.GetBytes(parameters));
            byte[] dataBlockMask = MGF1(copy, 0, hLen, mLen - hLen);
            int index = -1;
            for (int i = hLen; i < mLen; i++)
            {
                copy[i] ^= dataBlockMask[i - hLen];
                if (i < (hLen << 1))
                {
                    if (copy[i] != paramsHash[i - hLen])
                    {
                        return null;
                    }
                }
                else if (index == -1)
                {
                    if (copy[i] == 1)
                    {
                        index = i + 1;
                    }
                }
            }
            if (index == -1 || index == mLen)
            {
                return null;
            }
            byte[] unpadded = new byte[mLen - index];
            Array.Copy(copy, index, unpadded, 0, mLen - index);
            return unpadded;
        }

        static byte[] MGF1(byte[] seed, int seedOffset, int seedLength, int desiredLength)
        {
            int hLen = 32;
            int offset = 0;
            int i = 0;
            byte[] mask = new byte[desiredLength];
            byte[] temp = new byte[seedLength + 4];
            Array.Copy(seed, seedOffset, temp, 4, seedLength);
            while (offset < desiredLength)
            {
                temp[0] = (byte)(i >> 24);
                temp[1] = (byte)(i >> 16);
                temp[2] = (byte)(i >> 8);
                temp[3] = (byte)i;
                int remaining = desiredLength - offset;
                Array.Copy(SHA256(temp), 0, mask, offset, remaining < hLen ? remaining : hLen);
                offset = offset + hLen;
                i = i + 1;
            }
            return mask;
        }

        static byte[] SHA256(byte[] input)
        {
            return SHA256Cng.Create().ComputeHash(input);
        }

        static byte[] IntArrayToByteArray(int[] arr)
        {
            int length = arr.Length;
            byte[] res = new byte[length];
            for (int i = 0; i < length; i++)
            {
                res[i] = (byte)arr[i];
            }
            return res;
        }

        static int GenerateRandomPrime(int min_value, int max_value)
        {
            int cn = 0;
            while (true)
            {
                int num = random.Next(min_value, max_value);

                if (isPrime(num))
                {
                    Console.WriteLine("Loops: " + cn + " Prime selected: " + num);
                    return num;
                }
                cn += 1;
            }
        }

        static bool isPrime(int number)
        {
            int boundary = (int)Math.Floor(Math.Sqrt(number));

            if (number == 1) return false;
            if (number == 2) return true;

            for (int i = 2; i <= boundary; ++i)
            {
                if (number % i == 0) return false;
            }

            return true;
        }

        static void PrintArray(string text, int[] arr)
        {
            Console.Write(text);
            for (int i = 0; i < arr.Length; i++)
            {
                Console.Write(arr[i] + " ");
            }
            Console.WriteLine();
        }

        static void PrintArray(string text, byte[] arr)
        {
            Console.Write(text);
            for (int i = 0; i < arr.Length; i++)
            {
                Console.Write(arr[i] + " ");
            }
            Console.WriteLine();
        }

        static long ModuloPow(long value, long pow, long modulo)
        {
            long result = value;

            for (int i = 0; i < pow - 1; i++)
            {
                result = (result * value) % modulo;
            }
            return result;
        }

        /// <returns>All possible values ​​for the variable e</returns>
        static List<uint> GetAllPossibleE(uint phi)
        {
            uint task_share = phi / 4;

            uint task0_cycles = task_share;
            uint task1_cycles = task_share * 2;
            uint task2_cycles = task_share * 3;
            uint task3_cycles = phi;

            List<uint> result = new List<uint>();

            Task t0 = Task.Factory.StartNew(() =>
            {
                for (uint i = 2; i < task0_cycles; i++)
                {
                    if (ExtendedEuclidean(i, phi).gcd == 1)
                    {
                        result.Add(i);
                    }
                }
            });
            Task t1 = Task.Factory.StartNew(() =>
            {
                for (uint i = task0_cycles; i < task1_cycles; i++)
                {
                    if (ExtendedEuclidean(i, phi).gcd == 1)
                    {
                        result.Add(i);
                    }
                }
            });
            Task t2 = Task.Factory.StartNew(() =>
            {
                for (uint i = task1_cycles; i < task2_cycles; i++)
                {
                    if (ExtendedEuclidean(i, phi).gcd == 1)
                    {
                        result.Add(i);
                    }
                }
            });
            Task t3 = Task.Factory.StartNew(() =>
            {
                for (uint i = task2_cycles; i < task3_cycles; i++)
                {
                    if (ExtendedEuclidean(i, phi).gcd == 1)
                    {
                        result.Add(i);
                    }
                }
            });

            t0.Wait();
            t1.Wait();
            t2.Wait();
            t3.Wait();

            return result;
        }

        static ExtendedEuclideanResult ExtendedEuclidean(long a, long b)
        {
            long x0 = 1, xn = 1;
            long y0 = 0, yn = 0;
            long x1 = 0;
            long y1 = 1;
            long q;
            long r = a % b;

            while (r > 0)
            {
                q = a / b;
                xn = x0 - q * x1;
                yn = y0 - q * y1;

                x0 = x1;
                y0 = y1;
                x1 = xn;
                y1 = yn;
                a = b;
                b = r;
                r = a % b;
            }

            return new ExtendedEuclideanResult()
            {
                u1 = xn,
                u2 = yn,
                gcd = b
            };
        }

        struct ExtendedEuclideanResult
        {
            public long u1;
            public long u2;
            public long gcd;
        }

    }
}
