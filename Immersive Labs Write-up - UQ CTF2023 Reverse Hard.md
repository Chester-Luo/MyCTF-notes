# Immersive Labs Write-up - UQ CTF2023 Reverse Hard

## Description of problem

We are given a .exe program, we need to get flag from it.



## Analysis

We are asked to input 7-digits number at first:

![image-20230521021331427](/Users/luohaochen/Library/Application Support/typora-user-images/image-20230521021331427.png)

Then we enter the home page, we need to input something to get the flag.

![image-20230521021535944](/Users/luohaochen/Library/Application Support/typora-user-images/image-20230521021535944.png)

Obviously, we have no idea what need to input to get flag. Hence, we need further analysis. From the ice on the windows, we can infer that this is built from .NET.

.NET Reactor is a powerful reverse engineering tools for it. We download it and open .exe:

![image-20230521022025068](/Users/luohaochen/Library/Application Support/typora-user-images/image-20230521022025068.png)

It shows that the structure of origin project. It has two forms (login windows and main windows), and a external .dll file. We examine the source code for them, we can find something interesting:

![image-20230521022214854](/Users/luohaochen/Library/Application Support/typora-user-images/image-20230521022214854.png)

Here is a condition that how to check whether we have correct input to get the flag. It call function 'check' in the .dll

![image-20230521022309015](/Users/luohaochen/Library/Application Support/typora-user-images/image-20230521022309015.png)

OK, now we have already know the direction to move on, we export the source code and open it using IDE for better analysis.

![image-20230521022354970](/Users/luohaochen/Library/Application Support/typora-user-images/image-20230521022354970.png)

It can be exported as a .NET project perfectly:

![image-20230521022440389](/Users/luohaochen/Library/Application Support/typora-user-images/image-20230521022440389.png)

We start analysis the source code:

```c#
        private const int ssize = 0x80;
        private const int it = 100;
        public const string invalid = "flag{its_not_that_simple_unfortunately}";
        private string seedpass = "";
        private int _seed;
        public List<string> things;
        public List<string> things2;
```

It define some important variables at first, especially a fake flag lol... Then, it fill to arrays: things and things2:

```c#

        public amogus(int seed)
        {
            this._seed = seed;
            Rfc2898DeriveBytes bytes = new Rfc2898DeriveBytes(BitConverter.GetBytes(seed), Encoding.UTF8.GetBytes("susamogus"), 100);
            this.seedpass = Convert.ToBase64String(bytes.GetBytes(0x80));
            this.things = new List<string>(100);
            this.things2 = new List<string>(100);
            for (int i = 0; i < 100; i++)
            {
                this.things.Add("");
                this.things2.Add("");
                this.things[i] = Convert.ToBase64String(bytes.GetBytes(0x80));
                if (i != (seed % 100))
                {
                    Type[] types = new Type[] { typeof(string), typeof(string) };
                    object[] parameters = new object[] { this.seedpass, this.things[i] };
                    this.things2[i] = (string) Type.GetType(Encoding.UTF8.GetString(Convert.FromBase64String("Y29tcDMzMjBfY3RmMjAyMV9jaGFsbGRsbC5hbW9ndXMrU1RSQU5HRV9USElORw=="))).GetMethod(Encoding.UTF8.GetString(Convert.FromBase64String("U09fT0JGVVNDQVRFX05PVF9XT1dF")), types).Invoke(null, parameters);
                }
                else
                {
                    Type[] types = new Type[] { typeof(string), typeof(string) };
                    object[] parameters = new object[] { "iByysYOYmkXZSm9Ge5ENVi6fYfug0iGSRhAt2b8Fv1eGEnNDHRWBThC1A8o=", "susamogus" };
                    string str = (string) Type.GetType(Encoding.UTF8.GetString(Convert.FromBase64String("Y29tcDMzMjBfY3RmMjAyMV9jaGFsbGRsbC5hbW9ndXMrU1RSQU5HRV9USElORw=="))).GetMethod(Encoding.UTF8.GetString(Convert.FromBase64String("QkFLQV9NSVRBSQ==")), types).Invoke(null, parameters);
                    Type[] typeArray2 = new Type[] { typeof(string), typeof(string) };
                    object[] objArray2 = new object[] { Convert.ToBase64String(Encoding.UTF8.GetBytes(str + "_" + hash(this.seedpass) + "}")), this.things[i] };
                    this.things2[i] = (string) Type.GetType(Encoding.UTF8.GetString(Convert.FromBase64String("Y29tcDMzMjBfY3RmMjAyMV9jaGFsbGRsbC5hbW9ndXMrU1RSQU5HRV9USElORw=="))).GetMethod(Encoding.UTF8.GetString(Convert.FromBase64String("U09fT0JGVVNDQVRFX05PVF9XT1dF")), typeArray2).Invoke(null, objArray2);
                }
            }
        }
```

There are some string are encoded in BASE64, they are just class name and function name in .dll, not important. But we care about how data are processed.

Y29tcDMzMjBfY3RmMjAyMV9jaGFsbGRsbC5hbW9ndXMrU1RSQU5HRV9USElORw== means comp3320_ctf2021_challdll.amogus+STRANGE_THING

QkFLQV9NSVRBSQ== means BAKA_MITAI

U09fT0JGVVNDQVRFX05PVF9XT1dF means SO_OBFUSCATE_NOT_WOWE

We noticed that there is data (encrypted)-key pair:

```C#
object[] parameters = new object[] { "iByysYOYmkXZSm9Ge5ENVi6fYfug0iGSRhAt2b8Fv1eGEnNDHRWBThC1A8o=", "susamogus" };
```

The data in BASE64 has already been encrypted using algorithm in this code, "susamogus" is the key. In code, we can infer that the method "BAKA_MITAI" is decryption process.

```c#
          public static string BAKA_MITAI(string data, byte[] key) => 
                utf8.GetString(DAME_YO(data, key));

            public static string BAKA_MITAI(string data, string key) => 
                utf8.GetString(DAME_YO(data, key));

            public static byte[] DAME_DA_NE(byte[] data, byte[] key)
            {
                byte[] buffer2;
                if (data.Length == 0)
                {
                    buffer2 = null;
                }
                else
                {
                    byte[] buffer = ToByteArray(Decrypt(ToUInt32Array(data, false), ToUInt32Array(FixKey(key), false)), true);
                    buffer2 = ((buffer?.Length != 1) || (buffer[0] != 0)) ? buffer : null;
                }
                return buffer2;
            }
```

We notice that the index: seed%100 is special, it both used in generate process and check process. (It is easy to find that the seed is just 7-digits number we input).

```c#
        public bool check(string input)
        {
            int num = this._seed % 100;
            Type[] types = new Type[] { typeof(string), typeof(string) };
            object[] parameters = new object[] { Convert.ToBase64String(Encoding.UTF8.GetBytes(input)), this.things[num] };
            return (((string) Type.GetType(Encoding.UTF8.GetString(Convert.FromBase64String("Y29tcDMzMjBfY3RmMjAyMV9jaGFsbGRsbC5hbW9ndXMrU1RSQU5HRV9USElORw=="))).GetMethod(Encoding.UTF8.GetString(Convert.FromBase64String("U09fT0JGVVNDQVRFX05PVF9XT1dF")), types).Invoke(null, parameters)) == this.things2[num]);
        }

```

We can find that the relationship between this special element in both two arrays:

$things2[i]=\text{SO\_OBFUSCATE\_NOT\_WOWE}(str,things[i])$

$str=Plaintext\_hash(seedpass)\}$

Consider the structure, the Plaintext may start by "flag{" because the str ends by '}'.

In the check function, $correct\_input=\text{SO\_OBFUSCATE\_NOT\_WOWE}(input,things[i])=things2[i]$

Hence, we can find that the input is just str. Out task is using code we get now, to perform same process, which generates str.

## Solution

Based on above analysis, we can write a code:

```c#
using System.Text;
using System.Runtime.InteropServices;

using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;
using System.Reflection.Metadata;



namespace InteropDemo
{

    public class Program
    {


        public static void Main(string[] args)
        {

            int _seed = 1234567;
            Rfc2898DeriveBytes bytes = new Rfc2898DeriveBytes(BitConverter.GetBytes(_seed), Encoding.UTF8.GetBytes("susamogus"), 100);
            string seedpass = Convert.ToBase64String(bytes.GetBytes(0x80));
            string hashs = hash(seedpass);

            Type[] types = new Type[] { typeof(string), typeof(string) };
            Type[] typeArray2 = new Type[] { typeof(string), typeof(string) };
            string data1 = "iByysYOYmkXZSm9Ge5ENVi6fYfug0iGSRhAt2b8Fv1eGEnNDHRWBThC1A8o=";
            string key = "susamogus";
            string data = STRANGE_THING.BAKA_MITAI(data1, key);

            Console.WriteLine(data+'_'+hashs+'}');
            Console.Read();

        }

        public sealed class STRANGE_THING
        {
            private const string help = "Consider googling what delta and MX are";
            private static readonly UTF8Encoding utf8 = new UTF8Encoding();
            private const uint delta = 0x9e3779b9;

            private STRANGE_THING()
            {
            }

            public static string BAKA_MITAI(string data, byte[] key) =>
                utf8.GetString(DAME_YO(data, key));

            public static string BAKA_MITAI(string data, string key) =>
                utf8.GetString(DAME_YO(data, key));

            public static byte[] DAME_DA_NE(byte[] data, byte[] key)
            {
                byte[] buffer2;
                if (data.Length == 0)
                {
                    buffer2 = null;
                }
                else
                {
                    byte[] buffer = ToByteArray(Decrypt(ToUInt32Array(data, false), ToUInt32Array(FixKey(key), false)), true);
                    buffer2 = ((buffer?.Length != 1) || (buffer[0] != 0)) ? buffer : null;
                }
                return buffer2;
            }

            public static byte[] DAME_DA_NE(byte[] data, string key) =>
                DAME_DA_NE(data, utf8.GetBytes(key));

            public static string DAME_NA_NO(byte[] data, byte[] key) =>
                utf8.GetString(DAME_DA_NE(data, key));

            public static string DAME_NA_NO(byte[] data, string key) =>
                utf8.GetString(DAME_DA_NE(data, key));

            public static byte[] DAME_YO(string data, byte[] key) =>
                DAME_DA_NE(Convert.FromBase64String(data), key);

            public static byte[] DAME_YO(string data, string key) =>
                DAME_DA_NE(Convert.FromBase64String(data), key);

            private static unsafe uint[] Decrypt(uint[] v, uint[] k)
            {
                uint[] numArray;
                int index = v.Length - 1;
                if (index < 1)
                {
                    numArray = v;
                }
                else
                {
                    uint y = v[0];
                    uint sum = (uint)(((ulong)(6 + (0x34 / (index + 1)))) * 0x9e3779b9UL);

                    fixed (uint* vPtr = v) // Pin the 'v' array using the fixed statement
                    {
                        while (true)
                        {
                            if (sum == 0)
                            {
                                numArray = v;
                                break;
                            }

                            uint e = (sum >> 2) & 3;
                            int p = index;

                            while (true)
                            {
                                if (p <= 0)
                                {
                                    y = vPtr[0] -= MX(sum, y, v[index], p, e, k);
                                    sum -= 0x9e3779b9;
                                    break;
                                }

                                uint z = v[p - 1];
                                y = vPtr[p] -= MX(sum, y, z, p, e, k);
                                p--;
                            }
                        }
                    }
                }
                return numArray;
            }



            private static byte[] FixKey(byte[] key)
            {
                byte[] buffer2;
                if (key.Length == 0x10)
                {
                    buffer2 = key;
                }
                else
                {
                    byte[] array = new byte[0x10];
                    if (key.Length < 0x10)
                    {
                        key.CopyTo(array, 0);
                    }
                    else
                    {
                        Array.Copy(key, 0, array, 0, 0x10);
                    }
                    buffer2 = array;
                }
                return buffer2;
            }

            private static uint MX(uint sum, uint y, uint z, int p, uint e, uint[] k) =>
                (((z >> 5) ^ (y << 2)) + ((y >> 3) ^ (z << 4))) ^ ((sum ^ y) + (k[(int)((IntPtr)((p & 3) ^ e))] ^ z));


            private static byte[] ToByteArray(uint[] data, bool includeLength)
            {
                byte[] buffer2;
                int num = data.Length << 2;
                if (includeLength)
                {
                    int num2 = (int)data[data.Length - 1];
                    num -= 4;
                    if ((num2 >= (num - 3)) && (num2 <= num))
                    {
                        num = num2;
                    }
                    else
                    {
                        return null;
                    }
                }
                byte[] buffer = new byte[num];
                int index = 0;
                while (true)
                {
                    if (index >= num)
                    {
                        buffer2 = buffer;
                        break;
                    }
                    buffer[index] = (byte)(data[index >> 2] >> (((index & 3) << 3) & 0x1f));
                    index++;
                }
                return buffer2;
            }

            private static unsafe uint[] ToUInt32Array(byte[] data, bool includeLength)
            {
                uint[] numArray;
                int length = data.Length;
                int index = ((length & 3) == 0) ? (length >> 2) : ((length >> 2) + 1);
                if (!includeLength)
                {
                    numArray = new uint[index];
                }
                else
                {
                    numArray = new uint[index + 1];
                    numArray[index] = (uint)length;
                }

                fixed (uint* numPtr1 = numArray) // Pin the numArray variable using the fixed statement
                {
                    for (int i = 0; i < length; i++)
                    {
                        numPtr1[i >> 2] |= (uint)(data[i] << (((i & 3) << 3) & 0x1f));
                    }
                }

                return numArray;
            }

        }

        private static string hash(string rawData)
        {
            string str;
            using (SHA256 sha = SHA256.Create())
            {
                byte[] buffer = sha.ComputeHash(Encoding.UTF8.GetBytes(rawData));
                StringBuilder builder = new StringBuilder();
                int index = 0;
                while (true)
                {
                    if (index >= buffer.Length)
                    {
                        str = builder.ToString();
                        break;
                    }
                    builder.Append(buffer[index].ToString("x2"));
                    index++;
                }
            }
            return str;
        }

    }
}
```

We use the same hash function and encrypt-decrypt function. Notice, as the origin project may designed under .NET 4.0, I used VS2012 so that I need to make some change. Finally, it shows the flag:

![image-20230521024012105](/Users/luohaochen/Library/Application Support/typora-user-images/image-20230521024012105.png)