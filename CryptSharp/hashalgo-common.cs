/*######   Copyright (c) 2015 Ufasoft  http://ufasoft.com  mailto:support@ufasoft.com,  Sergey Pavlov  mailto:dev@ufasoft.com      ####
#                                                                                                                                     #
# 		See LICENSE for licensing information                                                                                         #
#####################################################################################################################################*/

using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;

namespace U.Crypto {

	public abstract class HashAlgoImp : HashAlgorithm {
		public int BlockSize = 128;

		protected byte[] m_state;

		byte[] m_block;
		int m_cbBlock;

		protected bool IsBlockCounted = false;
		protected bool IsLenBigEndian = true;
        private ulong m_count;
		private byte[] _ProcessingBuffer;   // Used to start data when passed less than a block worth.

		protected HashAlgoImp() {
			m_block = new byte[BlockSize];
        }

		protected abstract void HashBlock(byte[] data);

		protected virtual void OutTransform() { }

		public override void Initialize() {
			m_count = 0;
			m_cbBlock = 0;
			Array.Clear(m_block, 0, m_block.Length);
        }

		protected override void HashCore(byte[] array, int ibStart, int cbSize) {
			while (true) {
				int cb = Math.Min(cbSize, BlockSize - m_cbBlock);
				Array.Copy(array, ibStart, m_block, m_cbBlock, cb);
				ibStart += cb;
				cbSize -= cb;
                if ((m_cbBlock += cb) != BlockSize)
					break;
				m_count += (ulong)BlockSize;
                HashBlock(m_block);
				m_cbBlock = 0;
            }
		}

		protected override byte[] HashFinal() {
			ulong total = m_count + (ulong)m_cbBlock;
			if (m_cbBlock < BlockSize)
				m_block[m_cbBlock] = 0x80;
			for (int i = m_cbBlock + 1; i < BlockSize; ++i)
				m_block[i] = 0;
			if (m_cbBlock + 1 > BlockSize - 8) {
				HashBlock(m_block);
				Array.Clear(m_block, 0, BlockSize);
			}
			if (m_cbBlock == BlockSize)
				m_block[0] = 0x80;
			ulong len = IsBlockCounted ? (total + 8 + (ulong)BlockSize) / (ulong)BlockSize
				: total << 3;
			for (int i = 0; i < 8; ++i)
				m_block[BlockSize - i - 1] = (byte)(len >> (IsLenBigEndian ? i * 8 : 56 - i * 8));
			HashBlock(m_block);
			OutTransform();
			
			byte[] r = new byte[HashSize/8];
			Array.Copy(m_state, 0, r, 0, HashSize/8);
			State = 0;
			return r;
		}

		protected static ulong _rotl64(ulong v, int bits) {
			return (v << bits) | (v >> (64 - bits));
		}

		protected static void VectorXor(ulong[] d, ulong[] s) {
			for (int i = 0; i < d.Length; ++i)
				d[i] ^= s[i];
		}

		protected static void VectorXor(ulong[] d, ulong[] s, int len) {
			for (int i = 0; i < len; ++i)
				d[i] ^= s[i];
		}
	}
}

