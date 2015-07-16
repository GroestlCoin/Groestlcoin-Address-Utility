using System;
using U.Crypto;
using Org.BouncyCastle.Crypto.Digests;


namespace Coin {

public class Hasher {
	public static byte[] SHA256_SHA256(byte[] ba) {
		Sha256Digest bcsha256a = new Sha256Digest();
        bcsha256a.BlockUpdate(ba, 0, ba.Length);
		byte[] thehash = new byte[32];
        bcsha256a.DoFinal(thehash, 0);
        bcsha256a.BlockUpdate(thehash, 0, 32);
        bcsha256a.DoFinal(thehash, 0);
        return thehash;
	}


	public static byte[] GroestlHash(byte[] ar) {
		Groestl512Hash hf = new Groestl512Hash();
		byte[] h = hf.ComputeHash(hf.ComputeHash(ar)),
			r = new byte[32];
		Array.Copy(h, r, 32);
		return r;
	}
}


public class Global {
	public delegate byte[] DelegateHasher(byte[] ar);

	public static DelegateHasher HashForAddress = Hasher.GroestlHash;

}


}

namespace MessagingToolkit.QRCode.Codec { //!!!T

}
