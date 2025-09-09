# Cryptography

### Hashcrack

Author: Nana Ama Atombo-Sackey

### Description

A company stored a secret message on a server which got breached due to the admin using weakly hashed passwords. Can you gain access to the secret stored within the server?

Additional details will be available after launching your challenge instance.

![Screenshot 2025-09-06 184829.png](attachment:62cfa4fe-e3f2-4c53-a61a-ac6657544419:Screenshot_2025-09-06_184829.png)

### Mod 26

Author: Pandu

### Description

Cryptography can be easy, do you know what ROT13 is? `cvpbPGS{arkg_gvzr_V'yy_gel_2_ebhaqf_bs_ebg13_GYpXOHqX}`

**ROT13** is a simple letter [substitution cipher](https://en.wikipedia.org/wiki/Substitution_cipher) that replaces a letter with the 13th letter after it in the [Latin alphabet](https://en.wikipedia.org/wiki/Latin_alphabet).

ROT13 is a special case of the [Caesar cipher](https://en.wikipedia.org/wiki/Caesar_cipher) which was developed in ancient Rome, used by [Julius Caesar](https://en.wikipedia.org/wiki/Julius_Caesar) in the 1st century BC.[[1]](https://en.wikipedia.org/wiki/ROT13#cite_note-1) An early entry on the [Timeline of cryptography](https://en.wikipedia.org/wiki/Timeline_of_cryptography).

ROT13 can be referred by "Rotate13", "rotate by 13 places", hyphenated "ROT-13" or sometimes by its [autonym](https://en.wikipedia.org/wiki/Autological_word) "EBG13".

![image.png](attachment:257dfd6c-2169-4b53-963b-9da02718f097:image.png)

### The Numbers

Author: Danny

### Description

The [numbers](https://jupiter.challenges.picoctf.org/static/f209a32253affb6f547a585649ba4fda/the_numbers.png)... what do they mean?

HINT PROVIDED:

![image.png](attachment:b532b5de-b0b9-4385-bae3-e56bd0b9b619:image.png)

This looks like a **number-to-letter cipher**, most likely **A=1, B=2, …, Z=26**.

Let’s decode:

- **16 9 3 15 3 20 6**
    - 16 = P
    - 9 = I
    - 3 = C
    - 15 = O
    - 3 = C
    - 20 = T
    - 6 = F
        
        → **PICOTF**
        
- **20 8 5 14 21 13 2 5 18 19 13 1 19 15 14**
    - 20 = T
    - 8 = H
    - 5 = E
    - 14 = N
    - 21 = U
    - 13 = M
    - 2 = B
    - 5 = E
    - 18 = R
    - 19 = S
    - 13 = M
    - 1 = A
    - 19 = S
    - 15 = O
    - 14 = N
        
        → **THENUMBERSMASON**
        
        So the whole thing reads:
        
        picoctf{thenumbersmason}
        

### 13

Author: Alex Fulton/Daniel Tunitis

### Description

Cryptography can be easy, do you know what ROT13 is? `cvpbPGS{abg_gbb_onq_bs_n_ceboyrz}`

![image.png](attachment:2cfcf86a-2ac1-49c7-9368-835a5583dd87:image.png)

### interencdec

Author: NGIRIMANA Schadrack

### Description

Can you get the real meaning from this file.Download the file [here](https://artifacts.picoctf.net/c_titan/3/enc_flag).

[here](https://artifacts.picoctf.net/c_titan/3/enc_flag)

Hints:

Engaging in various decoding processes is of utmost importance

![image.png](attachment:39ee502d-baf6-4a38-ab74-58191185063b:image.png)

![image.png](attachment:c4043415-6cc3-42b3-899d-8d53e215a963:image.png)

![image.png](attachment:60af61c7-e922-4a27-b3c9-d2c97eb96ad7:image.png)

![image.png](attachment:6d9472d6-56cc-4730-9537-ad5d21e6a10f:image.png)

- **From Base64** (twice pehle hi kar liya)
- **ROT13 / Caesar Cipher** → Operation: **ROT-N**
    - Shift: **7**
    - Direction: **Decode (left shift)**

Base64 is a notation for encoding arbitrary byte data using a restricted set of symbols that can be conveniently used by humans and processed by computers.

This operation decodes data

**fr**

om an ASCII Base64 string back into its raw format.

e.g.

```
aGVsbG8=
```

becomes

```
hello
```

### EVEN RSA CAN BE BROKEN???

Author: Michael Crotty

### Description

This service provides you an encrypted flag. Can you decrypt it with just N & e?Connect to the program with netcat:`$ nc verbal-sleep.picoctf.net 51569`The program's source code can be downloaded [here](https://challenge-files.picoctf.net/c_verbal_sleep/68dea6cb63f53886d85611943a2abf0c22e38ce960966417f393cd053daee689/encrypt.py).

[here](https://challenge-files.picoctf.net/c_verbal_sleep/68dea6cb63f53886d85611943a2abf0c22e38ce960966417f393cd053daee689/encrypt.py)

from sys import exit
from Crypto.Util.number import bytes_to_long, inverse
from setup import get_primes

e = 65537

def gen_key(k):
"""
Generates RSA key with k bits
"""
p,q = get_primes(k//2)
N = p*q
d = inverse(e, (p-1)*(q-1))

```
return ((N,e), d)

```

def encrypt(pubkey, m):
N,e = pubkey
return pow(bytes_to_long(m.encode('utf-8')), e, N)

def main(flag):
pubkey, _privkey = gen_key(1024)
encrypted = encrypt(pubkey, flag)
return (pubkey[0], encrypted)

if **name** == "**main**":
flag = open('flag.txt', 'r').read()
flag = flag.strip()
N, cypher  = main(flag)
print("N:", N)
print("e:", e)
print("cyphertext:", cypher)
exit()

### What I did (short)

1. Factored NNN. It turned out to be even, so the factors are:

```
p = 2
q = 11857677260352208384117169986817086700026647292967486306289574907679320430566457558281627223560018290455854076615029016653405210492821320539247842887887409

```

1. Computed φ(N)=(p−1)(q−1)=q−1\varphi(N)=(p-1)(q-1)=q-1φ(N)=(p−1)(q−1)=q−1, then d=e−1  φ(N)d = e^{-1} \bmod \varphi(N)d=e−1modφ(N).
2. Decrypted m=cd  Nm = c^d \bmod Nm=cdmodN and converted to bytes → got the flag above.

Python script you can run locally to reproduce the decryption:

```python
from Crypto.Util.number import long_to_bytes, inverse

# Given values
N = 23715354520704416768234339973634173400053294585934972612579149815358640861132915116563254447120036580911708153230058033306810420985652641078495677185774818
e = 65537
c = 8869924420926276249803496027794335237794417691938411773005264252139116259551170694489580255496481399414219260391047787953937157003005276166415893293283855

# Factors of N
p = 2
q = N // p

# Euler totient
phi = (p - 1) * (q - 1)

# Private exponent
d = inverse(e, phi)

# Decrypt
m = pow(c, d, N)

# Convert to bytes
flag = long_to_bytes(m)
print(flag.decode())

```

👉 This should output:

```
picoCTF{tw0_1$_pr!m3df98b648}

```

### rotation

Author: Loic Shema

### Description

You will find the flag after decrypting this file
Download the encrypted flag [here](https://artifacts.picoctf.net/c/386/encrypted.txt).

[here](https://artifacts.picoctf.net/c/386/encrypted.txt)

### Hints

Sometimes rotation is right

![image.png](attachment:4c8244bf-84ae-4843-80f1-eb3134df743e:image.png)

### caesar

Author: Sanjay C/Daniel Tunitis

### Description

Decrypt this [message](https://jupiter.challenges.picoctf.org/static/6385b895dcb30c74dbd1f0ea271e3563/ciphertext).

---

*debug info: [u:880571 e: p: c:64 i:153]*

### Hints

caesar cipher [tutorial](https://learncryptography.com/classical-encryption/caesar-cipher)

![image.png](attachment:d496dbed-4449-4cd3-abc2-bbfc67fd23f1:image.png)

![image.png](attachment:d5a04b86-df82-4a6b-bfbb-e0719d497b80:image.png)

so the flag is 

picoCTF{**crossingtherubiconzaqjsscr}**

WEB EXPLOITATION
### dont-use-client-side

Author: Alex Fulton/Danny

### Description

Can you break into this super secure portal? `https://jupiter.challenges.picoctf.org/problem/29835/` ([link](https://jupiter.challenges.picoctf.org/problem/29835/)) or http://jupiter.challenges.picoctf.org:29835

![image.png](attachment:a87ea6eb-8c5e-44d8-a898-0d6f5d5f6fa1:image.png)

Conditions in order:

1. `substring(0,4) == "pico"` → **pico**
2. `substring(4,8) == "CTF{"` → **CTF{**
3. `substring(8,12) == "no_c"` → **no_c**
4. `substring(12,16) == "lien"` → **lien**
5. `substring(16,20) == "ts_p"` → **ts_p**
6. `substring(20,24) == "lz_7"` → **lz_7**
7. `substring(24,28) == "723c"` → **723c**
8. `substring(28,32) == "e}"` → **e}**

flag:picoCTF{no_clients_plz_7723ce}

### logon

Author: bobson

### Description

The factory is hiding things from all of its users. Can you login as Joe and find what they've been looking at? `https://jupiter.challenges.picoctf.org/problem/13594/` ([link](https://jupiter.challenges.picoctf.org/problem/13594/)) or http://jupiter.challenges.picoctf.org:13594

![image.png](attachment:0ced85fb-c413-4d75-92e5-04f03c8980a3:image.png)

Change:in application tab(in cookies) 

- `username` → `Joe`
- `admin` → `True`

![image.png](attachment:006360a5-b76e-4ac4-b051-b9308aaa1053:image.png)

### Insp3ct0r

Author: zaratec/danny

### Description

Kishor Balan tipped us off that the following code may need inspection: `https://jupiter.challenges.picoctf.org/problem/44924/` ([link](https://jupiter.challenges.picoctf.org/problem/44924/)) or http://jupiter.challenges.picoctf.org:44924

### Hints

How do you inspect web code on a browser?

There's 3 parts

### Insp3ct0r

Author: zaratec/danny

### Description

Kishor Balan tipped us off that the following code may need inspection: `https://jupiter.challenges.picoctf.org/problem/44924/` ([link](https://jupiter.challenges.picoctf.org/problem/44924/)) or http://jupiter.challenges.picoctf.org:44924

![image.png](attachment:21d94b74-b6ea-4cca-b152-9f0aeef10c5e:image.png)

![image.png](attachment:22a2f5a6-5223-4835-89a7-8cfeabb4ce6b:image.png)

![image.png](attachment:8680a8e5-398b-42fd-93ce-cea5d9bce29e:image.png)

so flag:picoCTF{tru3_d3t3ct1ve_0r_ju5t_lucky?f10be399}

### where are the robots

Author: zaratec/Danny

### Description

Can you find the robots? `https://jupiter.challenges.picoctf.org/problem/36474/` ([link](https://jupiter.challenges.picoctf.org/problem/36474/)) or http://jupiter.challenges.picoctf.org:36474

---

*debug info: [u:880571 e: p: c:4 i:365]*

### Hints

What part of the website could tell you where the creator doesn't want you to look?

- Open the base site:
    
    ```
    http://jupiter.challenges.picoctf.org:36474/
    
    ```
    
    It only shows a simple message: *“Where are the robots?”*
    
- Append `/robots.txt` to the URL (standard trick in CTFs):
    
    ```
    http://jupiter.challenges.picoctf.org:36474/robots.txt
    
    ```
    
    This shows:
    
    ```
    User-agent: *
    Disallow: /477ce.html
    
    ```
    
- Visit the disallowed page:
    
    ```
    http://jupiter.challenges.picoctf.org:36474/477ce.html
    
    ```
    
- That page contains the **flag**.

![image.png](attachment:33a9dc31-e7ac-45d8-a3ea-cdb62d5c79be:image.png)

### Client-side-again

Author: Danny

### Description

Can you break into this super secure portal? `https://jupiter.challenges.picoctf.org/problem/60786/` ([link](https://jupiter.challenges.picoctf.org/problem/60786/)) or http://jupiter.challenges.picoctf.org:60786

---

*debug info: [u:880571 e: p: c:69 i:334]*

### Hints

What is obfuscation?

**Array of strings**

JS :

var _0x5a46=[
'f49bf}',    // [0]
'_again_e',  // [1]
'this',      // [2]
'Password Verified',
'Incorrect password',
'getElementById',
'value',
'substring',
'picoCTF{',  // [8]
'not_this'   // [9]
];

### Code logic (simplified)

```jsx
function verify() {
  checkpass = document.getElementById('pass').value;
  split = 4;

  if (checkpass.substring(0, 8) == "picoCTF{") {
    if (checkpass.substring(7, 9) == "{n") {
      if (checkpass.substring(8, 16) == "not_this") {
        if (checkpass.substring(3, 6) == "oCT") {
          if (checkpass.substring(16, 24) == "_again_e") {
            if (checkpass.substring(6, 11) == "F{not") {
              if (checkpass.substring(24, 29) == "f49bf}") {
                if (checkpass.substring(12, 16) == "this") {
                  alert("Password Verified");
                }
              }
            }
          }
        }
      }
    }
  } else {
    alert("Incorrect password");
  }
}

```

---

### 3. Extracting the flag pieces

From conditions:

- `substring(0,8)` → `picoCTF{`
- `substring(8,16)` → `not_this`
- `substring(12,16)` → `this` ✅ (fits inside `not_this`)
- `substring(16,24)` → `_again_e`
- `substring(24,29)` → `f49bf}`
- Combined:
    
    ```
    picoCTF{not_this_again_ef49bf}
    
    ```
    FORENSICS
  ### information

Author: susie

### Description

Files can always be changed in a secret way. Can you find the flag? [cat.jpg](https://mercury.picoctf.net/static/b4d62f6e431dc8e563309ea8c33a06b3/cat.jpg)

![image.png](attachment:7fd99c4e-b030-40d3-876f-8fa0ab951549:fb3161aa-5374-4cca-894e-e1b2d8c6584f.png)

Then we decode the string using cyberchef

![image.png](attachment:ff8b03d2-319c-4415-9ace-f2693f78d4bb:image.png)

GENERAL SKILLS
### 2Warm

Author: Sanjay C/Danny Tunitis

### Description

Can you convert the number 42 (base 10) to binary (base 2)?

---

*debug info: [u:880571 e: p: c:86 i:206]*

### Hints

Submit your answer in our competition's flag format. For example, if your answer was '11111', you would submit 'picoCTF{11111}' as the flag.

Let’s convert **42 (base 10)** to **binary (base 2)** step by step.

We repeatedly divide by 2 and note the remainders:

- 42÷2=2142 \div 2 = 2142÷2=21 remainder **0**
- 21÷2=1021 \div 2 = 1021÷2=10 remainder **1**
- 10÷2=510 \div 2 = 510÷2=5 remainder **0**
- 5÷2=25 \div 2 = 25÷2=2 remainder **1**
- 2÷2=12 \div 2 = 12÷2=1 remainder **0**
- 1÷2=01 \div 2 = 01÷2=0 remainder **1**

flag:  picoCTF{101010}

### First Grep

Author: Alex Fulton/Danny Tunitis

### Description

Can you find the flag in [file](https://jupiter.challenges.picoctf.org/static/515f19f3612bfd97cd3f0c0ba32bd864/file)? This would be really tedious to look through manually, something tells me there is a better way.

![image.png](attachment:0d77456b-d473-4ec2-b617-ca3cccd60e39:image.png)

### Bases

Author: Sanjay C/Danny T

### Description

What does this `bDNhcm5fdGgzX3IwcDM1` mean? I think it has something to do with bases.

![image.png](attachment:54cf31cd-bf59-4359-9586-5df553133a14:image.png)

### Warmed Up

Author: Sanjay C/Danny Tunitis

### Description

What is 0x3D (base 16) in decimal (base 10)?

Let’s convert **0x3D (hexadecimal)** to decimal:

- 3D16=(3×161)+(D×160)3D_{16} = (3 \times 16^1) + (D \times 16^0)3D16=(3×161)+(D×160)
- 3×16=483 \times 16 = 483×16=48
- D=13D = 13D=13
- 48+13=6148 + 13 = 6148+13=61

✅ So, **0x3D (base 16) = 61 (base 10)**

flag:picoCTF{61}

### Lets Warm Up

Author: Sanjay C/Danny Tunitis

### Description

If I told you a word started with 0x70 in hexadecimal, what would it start with in ASCII?

Let's solve this **step by step**.

1. **Given:** The word starts with `0x70` in hexadecimal.
    - `0x70` is a hex representation of a number.
2. **Convert hex to decimal:**
    - `0x70` → 7×16+0=1127 \times 16 + 0 = 1127×16+0=112 in decimal.
3. **Convert decimal to ASCII:**
    - ASCII code `112` corresponds to the character `'p'`.

✅ **Answer:** The word would start with **`p`** in ASCII.

so the flag : picoCTF{p}

REVERSE ENGINEERING
### vault-door-training

Author: Mark E. Haase

### Description

Your mission is to enter Dr. Evil's laboratory and retrieve the blueprints for his Doomsday Project. The laboratory is protected by a series of locked vault doors. Each door is controlled by a computer and requires a password to open. Unfortunately, our undercover agents have not been able to obtain the secret passwords for the vault doors, but one of our junior agents obtained the source code for each vault's computer! You will need to read the source code for each level to figure out what the password is for that vault door. As a warmup, we have created a replica vault in our training facility. The source code for the training vault is here: [VaultDoorTraining.java](https://jupiter.challenges.picoctf.org/static/a4a1ca9c54d8fac9404f9cbc50d9751a/VaultDoorTraining.java)

Hints

---

The password is revealed in the program's source code.

![image.png](attachment:d156bd52-802a-415e-8242-0bbed033945a:image.png)

so the flag is picoCTF{w4rm1ng_Up_w1tH_jAv4_be8d9806f18}

### vault-door-5

Author: Mark E. Haase

### Description

In the last challenge, you mastered octal (base 8), decimal (base 10), and hexadecimal (base 16) numbers, but this vault door uses a different change of base as well as URL encoding! The source code for this vault is here: [VaultDoor5.java](https://jupiter.challenges.picoctf.org/static/0a53bf0deaba6919f98d8550c35aa253/VaultDoor5.java)

---

*debug info: [u:880571 e: p: c:77 i:184]*

### Hints

You may find an encoder/decoder tool helpful, such as https://encoding.tools/

Read the wikipedia articles on URL encoding and base 64 encoding to understand how they work and what the results look like.

```java
import java.net.URLDecoder;
import java.util.*;

class VaultDoor5 {
    public static void main(String args[]) {
        VaultDoor5 vaultDoor = new VaultDoor5();
        Scanner scanner = new Scanner(System.in);
        System.out.print("Enter vault password: ");
        String userInput = scanner.next();
	String input = userInput.substring("picoCTF{".length(),userInput.length()-1);
	if (vaultDoor.checkPassword(input)) {
	    System.out.println("Access granted.");
	} else {
	    System.out.println("Access denied!");
        }
    }

    // Minion #7781 used base 8 and base 16, but this is base 64, which is
    // like... eight times stronger, right? Riiigghtt? Well that's what my twin
    // brother Minion #2415 says, anyway.
    //
    // -Minion #2414
    public String base64Encode(byte[] input) {
        return Base64.getEncoder().encodeToString(input);
    }

    // URL encoding is meant for web pages, so any double agent spies who steal
    // our source code will think this is a web site or something, defintely not
    // vault door! Oh wait, should I have not said that in a source code
    // comment?
    //
    // -Minion #2415
    public String urlEncode(byte[] input) {
        StringBuffer buf = new StringBuffer();
        for (int i=0; i<input.length; i++) {
            buf.append(String.format("%%%2x", input[i]));
        }
        return buf.toString();
    }

    public boolean checkPassword(String password) {
        String urlEncoded = urlEncode(password.getBytes());
        String base64Encoded = base64Encode(urlEncoded.getBytes());
        String expected = "JTYzJTMwJTZlJTc2JTMzJTcyJTc0JTMxJTZlJTY3JTVm"
                        + "JTY2JTcyJTMwJTZkJTVmJTYyJTYxJTM1JTY1JTVmJTM2"
                        + "JTM0JTVmJTMwJTYyJTM5JTM1JTM3JTYzJTM0JTY2";
        return base64Encoded.equals(expected);
    }
}

```

### Understand the logic

The checkPassword() function works like this:

```java
public boolean checkPassword(String password) {
    String urlEncoded = urlEncode(password.getBytes());      // Step 1: URL-encode
    String base64Encoded = base64Encode(urlEncoded.getBytes()); // Step 2: Base64-encode
    String expected = "...";  // The final encoded string
    return base64Encoded.equals(expected);
}

```

So:

**password → URL-encoded → Base64-encoded → compared to expected**

Our job is to **reverse this process**.

### Expected value

From code:

```
JTYzJTMwJTZlJTc2JTMzJTcyJTc0JTMxJTZlJTY3JTVm
JTY2JTcyJTMwJTZkJTVmJTYyJTYxJTM1JTY1JTVmJTM2
JTM0JTVmJTMwJTYyJTM5JTM1JTM3JTYzJTM0JTY2

```

Concatenate:

JTYzJTMwJTZlJTc2JTMzJTcyJTc0JTMxJTZlJTY3JTVmJTY2JTcyJTMwJTZkJTVmJTYyJTYxJTM1JTY1JTVmJTM2JTM0JTVmJTMwJTYyJTM5JTM1JTM3JTYzJTM0JTY2

### Base64 decode

Decoding that base64 string gives us:

![image.png](attachment:977499b4-82dd-4350-b069-38b7328ed55a:image.png)

now using url decode to decode this %63%30%6e%76%33%72%74%31%6e%67%5f%66%72%30%6d%5f%62%61%35%65%5f%36%34%5f%30%62%39%35%37%63%34%66

![image.png](attachment:006c0422-24ae-490e-b4eb-09f9468acad1:image.png)

so the flag is

 picoCTF{c0nv3rt1ng_fr0m_ba5e_64_0b957c4f}

### vault-door-4

Author: Mark E. Haase

### Description

This vault uses ASCII encoding for the password. The source code for this vault is here: [VaultDoor4.java](https://jupiter.challenges.picoctf.org/static/834acd392e0964a41f05790655a994b9/VaultDoor4.java)

```java
import java.util.*;

class VaultDoor4 {
    public static void main(String args[]) {
        VaultDoor4 vaultDoor = new VaultDoor4();
        Scanner scanner = new Scanner(System.in);
        System.out.print("Enter vault password: ");
        String userInput = scanner.next();
	String input = userInput.substring("picoCTF{".length(),userInput.length()-1);
	if (vaultDoor.checkPassword(input)) {
	    System.out.println("Access granted.");
	} else {
	    System.out.println("Access denied!");
        }
    }

    // I made myself dizzy converting all of these numbers into different bases,
    // so I just *know* that this vault will be impenetrable. This will make Dr.
    // Evil like me better than all of the other minions--especially Minion
    // #5620--I just know it!
    //
    //  .:::.   .:::.
    // :::::::.:::::::
    // :::::::::::::::
    // ':::::::::::::'
    //   ':::::::::'
    //     ':::::'
    //       ':'
    // -Minion #7781
    public boolean checkPassword(String password) {
        byte[] passBytes = password.getBytes();
        byte[] myBytes = {
            106 , 85  , 53  , 116 , 95  , 52  , 95  , 98  ,
            0x55, 0x6e, 0x43, 0x68, 0x5f, 0x30, 0x66, 0x5f,
            0142, 0131, 0164, 063 , 0163, 0137, 0146, 064 ,
            'a' , '8' , 'c' , 'd' , '8' , 'f' , '7' , 'e' ,
        };
        for (int i=0; i<32; i++) {
            if (passBytes[i] != myBytes[i]) {
                return false;
            }
        }
        return true;
    }
}

```

### Step 1: Array values

```java
byte[] myBytes = {
    106 , 85  , 53  , 116 , 95  , 52  , 95  , 98  ,
    0x55, 0x6e, 0x43, 0x68, 0x5f, 0x30, 0x66, 0x5f,
    0142, 0131, 0164, 063 , 0163, 0137, 0146, 064 ,
    'a' , '8' , 'c' , 'd' , '8' , 'f' , '7' , 'e' ,
};

```

- Decimal: `106, 85, 53, 116 …`
- Hex: `0x55, 0x6e …`
- Octal: `0142, 0131 …`
- Direct chars: `'a','8','c','d'...`

### Convert each to ASCII

- 106 → `j`
- 85 → `U`
- 53 → `5`
- 116 → `t`
- 95 → `_`
- 52 → `4`
- 95 → `_`
- 98 → `b`
- 0x55 = 85 → `U`
- 0x6e = 110 → `n`
- 0x43 = 67 → `C`
- 0x68 = 104 → `h`
- 0x5f = 95 → `_`
- 0x30 = 48 → `0`
- 0x66 = 102 → `f`
- 0x5f = 95 → `_`
- 0142 (octal) = 98 → `b`
- 0131 (octal) = 89 → `Y`
- 0164 (octal) = 116 → `t`
- 063 (octal) = 51 → `3`
- 0163 (octal) = 115 → `s`
- 0137 (octal) = 95 → `_`
- 0146 (octal) = 102 → `f`
- 064 (octal) = 52 → `4`
- `'a'` → `a`
- `'8'` → `8`
- `'c'` → `c`
- `'d'` → `d`
- `'8'` → `8`
- `'f'` → `f`
- `'7'` → `7`
- `'e'` → `e`

### Combine

```
jU5t_4_bUnCh_0f_bYt3s_f4a8cd8f7e

```

so the flag is

picoCTF{jU5t_4_bUnCh_0f_bYt3s_f4a8cd8f7e}
