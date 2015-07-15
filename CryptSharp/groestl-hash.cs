/*######   Copyright (c) 2015 Ufasoft  http://ufasoft.com  mailto:support@ufasoft.com,  Sergey Pavlov  mailto:dev@ufasoft.com      ####
#                                                                                                                                     #
# 		See LICENSE for licensing information                                                                                         #
#####################################################################################################################################*/

using System;
using System.IO;
using System.Security.Cryptography;

namespace U.Crypto {
	public class Groestl512Hash : HashAlgoImp {


		static readonly byte[] g_aesSubByte = new byte[256] {
			0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
			0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
			0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
			0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
			0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
			0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
			0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
			0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
			0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
			0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
			0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
			0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
			0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
			0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
			0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
			0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
		};

		static readonly byte[] g_aesPowers = new byte[1024],
			g_aesInvSubByte = new byte[256];
		static readonly UInt16[] g_aesLogs = new UInt16[256];

		static readonly UInt64[,] g_groestl_T_table = new UInt64[8,256];

		static readonly byte[] s_shiftTableP1024 = new byte[16] { 0, 1, 2, 3, 4, 5, 6, 11, 0, 0, 0, 0, 0, 0, 0, 0 };
		static readonly byte[] s_shiftTableQ1024 = new byte[16] { 1, 3, 5, 11, 0, 2, 4, 6, 0, 0, 0, 0, 0, 0, 0, 0 };

		static readonly UInt64[,] g_groestl_RoundConstants_P = new UInt64[15, 16],
			g_groestl_RoundConstants_Q = new UInt64[15, 16];

		static byte Mul(byte a, byte b) {
			return g_aesPowers[g_aesLogs[a] + g_aesLogs[b]];
		}

		static void ExtendTable(byte[] t) {
			for (int row = 0; row < 8; ++row)
				t[row + 8] = (byte)(8 * t[row] + row);
		}

		static Groestl512Hash() {
			byte n = 0;
			for (int i = 0; i < 256; ++i) {
				g_aesInvSubByte[g_aesSubByte[i]] = (byte)i;
				g_aesLogs[g_aesPowers[i] = n = (byte)(i == 0 ? 1 : n ^ (n << 1) ^ ((n & 0x80) != 0 ? 0x1B : 0))] = (byte)i;
			}
			Array.Copy(g_aesPowers, 0, g_aesPowers, 255, 255);
			g_aesLogs[1] = 0;
			g_aesLogs[0] = 511;         // means -INFINITY

			ExtendTable(s_shiftTableP1024);
			ExtendTable(s_shiftTableQ1024);

			for (int i = 0; i < 256; ++i) {
				byte a = g_aesSubByte[i];
				byte[] p = new byte[8];
				p[7] = p[0] = Mul(2, a);
				p[6] = p[3] = Mul(3, a);
				p[5] = Mul(4, a);
				p[4] = p[2] = Mul(5, a);
				p[1] = Mul(7, a);

				g_groestl_T_table[0, i] = BitConverter.ToUInt64(p, 0);

				for (int row = 1; row < 8; ++row)
					g_groestl_T_table[row, i] = _rotl64(g_groestl_T_table[0, i], row * 8);
			}

			for (int i = 0; i < 14; ++i) {
				byte v = (byte)i;
				for (int c = 0; c < 16; ++c, v += 0x10) {
					g_groestl_RoundConstants_P[i, c] ^= v;
					g_groestl_RoundConstants_Q[i, c] ^= 0xFFFFFFFFFFFFFFFF ^ ((UInt64)((c << 4) | i) << 56);
				}
			}
		}

		public Groestl512Hash() {
			HashSizeValue = 512;
			BlockSize = 128;
			IsBlockCounted = true;
			Initialize();
		}

		public override void Initialize() {
			m_state = new byte[128];
			m_state[m_state.Length - 2] = 2;
			base.Initialize();
		}

		UInt64[] ToUInt64Array(byte[] ar) {
			UInt64[] r = new UInt64[ar.Length / 8];
			for (int i = 0; i < r.Length; ++i) {
				for (int j = 0; j < 8; ++j)
					r[i] |= (UInt64)ar[i * 8 + j] << j * 8;
			}
			return r;
		}

		byte GetByte(UInt64[] ar, int i) {
			UInt64 v = ar[i / 8];
			return (byte)(v >> (i % 8) * 8);
		}

		void TransformBlock1024(UInt64[] s, UInt64[,] roundConstants, byte[] shiftTable) {
			const int cols = 16;
			int maskCols = cols - 1, maskCols8 = (maskCols << 3) | 7;
			UInt64[] t = new UInt64[16],
				u = new UInt64[32],
				pT = t, pU = u;
			Array.Copy(s, 0, u, 0, cols);

			for (int i = 0; i < 14; ++i) {

				for (int c = 0; c < cols; ++c)                                    // AddRoundConstant
					pU[c] ^= roundConstants[i, c];
				for (int c = 0; c < cols; ++c) {
					UInt64 col = 0;
					for (int row = 0; row < 8; ++row)
						col ^= g_groestl_T_table[row, GetByte(pU, (c * 8 + shiftTable[8+row]) & maskCols8)];
					pT[c] = col;
				}
				var tt = pT;
				pT = pU;
				pU = tt;
			}

			for (int c=0; c<cols; ++c) {
				ulong v = pU[c];
				for (int i = 0; i < 8; ++i)
					m_state[c * 8 + i] ^= (byte)(v >> i * 8); ;
			}
		}

		void P1024(UInt64[] s) {
			TransformBlock1024(s, g_groestl_RoundConstants_P, s_shiftTableP1024);
		}

		void Q1024(UInt64[] s) {
			TransformBlock1024(s, g_groestl_RoundConstants_Q, s_shiftTableQ1024);
		}

		override protected void HashBlock(byte[] src) {
			UInt64[] hm = ToUInt64Array(m_state),
				src64 = ToUInt64Array(src);
			VectorXor(hm, src64);

			P1024(hm);
			Q1024(src64);
		}

		protected override void OutTransform() {
			P1024(ToUInt64Array(m_state));
			Array.Copy(m_state, 64, m_state, 0, 64);
		}


		public ushort htobe(ushort x) {
			return (ushort)((ushort)((x & 0xff) << 8) | ((x >> 8) & 0xff));
		}
	}
}

