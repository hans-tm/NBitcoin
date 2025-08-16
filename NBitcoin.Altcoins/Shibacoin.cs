using NBitcoin;
using NBitcoin.DataEncoders;
using NBitcoin.Protocol;
using NBitcoin.RPC;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Threading.Tasks;
using System.Reflection;

namespace NBitcoin.Altcoins
{
	// Reference: https://github.com/shibacoinppc/shibacoin/blob/v1.2.1/src/chainparams.cpp
	public class Shibacoin : NetworkSetBase
	{
		public static Shibacoin Instance { get; } = new Shibacoin();

		public override string CryptoCode => "SHIC";

		private Shibacoin()
		{

		}
		public class ShibaConsensusFactory : ConsensusFactory
		{
			private ShibaConsensusFactory()
			{
			}
			public static ShibaConsensusFactory Instance { get; } = new ShibaConsensusFactory();

			public override BlockHeader CreateBlockHeader()
			{
				return new ShibacoinBlockHeader();
			}
			public override Block CreateBlock()
			{
				return new ShibacoinBlock(new ShibacoinBlockHeader());
			}
			public override Transaction CreateTransaction()
			{
				return new ShibaTransaction();
			}
			public override TxOut CreateTxOut()
			{
				return new ShibaTxOut();
			}
			protected override TransactionBuilder CreateTransactionBuilderCore(Network network)
			{
				// https://github.com/shibacoinppc/shibacoin/blob/v1.2.1/doc/fee-recommendation.md
				var txBuilder = base.CreateTransactionBuilderCore(network);
				txBuilder.StandardTransactionPolicy.MinRelayTxFee = new FeeRate(Money.Coins(0.001m), 1000);
				// Around 0.003 USD of fee for a transaction at ~0.00003 USD per shic
				txBuilder.StandardTransactionPolicy.MaxTxFee = new FeeRate(Money.Coins(56m), 1);
				return txBuilder;
			}
		}

#pragma warning disable CS0618 // Type or member is obsolete
		public class AuxPow : IBitcoinSerializable
		{
			Transaction tx = new Transaction();

			public Transaction Transactions
			{
				get
				{
					return tx;
				}
				set
				{
					tx = value;
				}
			}

			uint nIndex = 0;

			public uint Index
			{
				get
				{
					return nIndex;
				}
				set
				{
					nIndex = value;
				}
			}

			uint256 hashBlock = new uint256();

			public uint256 HashBlock
			{
				get
				{
					return hashBlock;
				}
				set
				{
					hashBlock = value;
				}
			}

			List<uint256> vMerkelBranch = new List<uint256>();

			public List<uint256> MerkelBranch
			{
				get
				{
					return vMerkelBranch;
				}
				set
				{
					vMerkelBranch = value;
				}
			}

			List<uint256> vChainMerkleBranch = new List<uint256>();

			public List<uint256> ChainMerkleBranch
			{
				get
				{
					return vChainMerkleBranch;
				}
				set
				{
					vChainMerkleBranch = value;
				}
			}

			uint nChainIndex = 0;

			public uint ChainIndex
			{
				get
				{
					return nChainIndex;
				}
				set
				{
					nChainIndex = value;
				}
			}

			BlockHeader parentBlock = new BlockHeader();

			public BlockHeader ParentBlock
			{
				get
				{
					return parentBlock;
				}
				set
				{
					parentBlock = value;
				}
			}

			public void ReadWrite(BitcoinStream stream)
			{
				stream.ReadWrite(ref tx);
				stream.ReadWrite(ref hashBlock);
				stream.ReadWrite(ref vMerkelBranch);
				stream.ReadWrite(ref nIndex);
				stream.ReadWrite(ref vChainMerkleBranch);
				stream.ReadWrite(ref nChainIndex);
				stream.ReadWrite(ref parentBlock);
			}
		}
		public class DogeTransaction : Transaction
		{
			public override ConsensusFactory GetConsensusFactory()
			{
				return Shibacoin.ShibaConsensusFactory.Instance;
			}
		}
		public class ShibaTxOut : TxOut
		{
			public override Money GetDustThreshold()
			{
				// https://github.com/shibacoinppc/shibacoin/blob/v1.2.1/doc/fee-recommendation.md
				return Money.Coins(0.01m);
			}
			public override ConsensusFactory GetConsensusFactory()
			{
				return Shibacoin.ShibaConsensusFactory.Instance;
			}
		}
		public class ShibacoinBlock : Block
		{
			public ShibacoinBlock(ShibacoinBlockHeader header) : base(header)
			{

			}

			public override ConsensusFactory GetConsensusFactory()
			{
				return ShibaConsensusFactory.Instance;
			}
		}
		public class ShibacoinBlockHeader : BlockHeader
		{
			const int VERSION_AUXPOW = (1 << 8);

			AuxPow auxPow = new AuxPow();

			public AuxPow AuxPow
			{
				get
				{
					return auxPow;
				}
				set
				{
					auxPow = value;
				}
			}

			public override uint256 GetPoWHash()
			{
				var headerBytes = this.ToBytes();
				var h = NBitcoin.Crypto.SCrypt.ComputeDerivedKey(headerBytes, headerBytes, 1024, 1, 1, null, 32);
				return new uint256(h);
			}

			public override void ReadWrite(BitcoinStream stream)
			{
				base.ReadWrite(stream);
				if((Version & VERSION_AUXPOW) != 0)
				{
					if(!stream.Serializing)
					{
						stream.ReadWrite(ref auxPow);
					}
				}
			}
		}

		public class ShibacoinTestnetAddressStringParser : NetworkStringParser
		{
			public override bool TryParse(string str, Network network, Type targetType, out IBitcoinString result)
			{
				if (str.StartsWith("tgpv", StringComparison.OrdinalIgnoreCase) && targetType.GetTypeInfo().IsAssignableFrom(typeof(BitcoinExtKey).GetTypeInfo()))
				{
					try
					{
						var decoded = Encoders.Base58Check.DecodeData(str);
						decoded[0] = 0x04;
						decoded[1] = 0x35;
						decoded[2] = 0x83;
						decoded[3] = 0x94;
						result = new BitcoinExtKey(Encoders.Base58Check.EncodeData(decoded), network);
						return true;
					}
					catch
					{
					}
				}
				if (str.StartsWith("tgub", StringComparison.OrdinalIgnoreCase) && targetType.GetTypeInfo().IsAssignableFrom(typeof(BitcoinExtPubKey).GetTypeInfo()))
				{
					try
					{
						var decoded = Encoders.Base58Check.DecodeData(str);
						decoded[0] = 0x04;
						decoded[1] = 0x35;
						decoded[2] = 0x87;
						decoded[3] = 0xCF;
						result = new BitcoinExtPubKey(Encoders.Base58Check.EncodeData(decoded), network);
						return true;
					}
					catch
					{
					}
				}
				return base.TryParse(str, network, targetType, out result);
			}
		}

#pragma warning restore CS0618 // Type or member is obsolete

		//Format visual studio
		//{({.*?}), (.*?)}
		//Tuple.Create(new byte[]$1, $2)
		//static Tuple<byte[], int>[] pnSeed6_main = null;
		//static Tuple<byte[], int>[] pnSeed6_test = null;
		// Not used in SHIC: https://github.com/shibacoinppc/shibacoin/blob/v1.2.1/src/chainparams.cpp

		protected override NetworkBuilder CreateMainnet()
		{
			var builder = new NetworkBuilder();
			builder.SetConsensus(new Consensus()
			{
				SubsidyHalvingInterval = 100000,
				MajorityEnforceBlockUpgrade = 1500,
				MajorityRejectBlockOutdated = 1900,
				MajorityWindow = 2000,
				PowLimit = new Target(new uint256("00000fffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")),
				PowTargetTimespan = TimeSpan.FromSeconds(60),
				PowTargetSpacing = TimeSpan.FromSeconds(60),
				PowAllowMinDifficultyBlocks = false,
				CoinbaseMaturity = 30,
				//  Not set in reference client, assuming false
				PowNoRetargeting = false,
				RuleChangeActivationThreshold = 9576,
				MinerConfirmationWindow = 10080,
				ConsensusFactory = ShibaConsensusFactory.Instance,
				LitecoinWorkCalculation = true,
				SupportSegwit = false
			})
			.SetBase58Bytes(Base58Type.PUBKEY_ADDRESS, new byte[] { 63 })
			.SetBase58Bytes(Base58Type.SCRIPT_ADDRESS, new byte[] { 22 })
			.SetBase58Bytes(Base58Type.SECRET_KEY, new byte[] { 158 })
			.SetBase58Bytes(Base58Type.EXT_PUBLIC_KEY, new byte[] { 0x02, 0xFA, 0xDA, 0xFE })
			.SetBase58Bytes(Base58Type.EXT_SECRET_KEY, new byte[] { 0x02, 0xFA, 0xC4, 0x95 })
			.SetBech32(Bech32Type.WITNESS_PUBKEY_ADDRESS, Encoders.Bech32("shic"))
			.SetBech32(Bech32Type.WITNESS_SCRIPT_ADDRESS, Encoders.Bech32("shic"))
			.SetMagic(0xf0e0c0b0)
			.SetPort(33864)
			.SetRPCPort(33863)
			.SetName("shic-main")
			.AddAlias("shic-mainnet")
			.AddAlias("shibacoin-mainnet")
			.AddAlias("shibacoin-main")
			.SetUriScheme("shibacoin")
			.AddDNSSeeds(new[]
			{
				new DNSSeedData("shibacoinshic.org", "seeds.shibacoinshic.org")
			})
			.AddSeeds(new NetworkAddress[0])
			.SetGenesis("010000000000000000000000000000000000000000000000000000000000000000000000450f8ab5cade1c53c2ef36d655076fd0a114378cc54678073b966dff820459e40c845f67f0ff0f1ef98901000101000000010000000000000000000000000000000000000000000000000000000000000000ffffffff3704ffff001d01042f4e617364617120746f20416464204d6963726f537472617465677920746f20746865204e617331303020496e646578ffffffff010058850c0200000043410404721c4861d9047841a25fb469f98ba09e8c9134a4e0ebfb5c84f5e6969e35911d39e492dc2dda8dc84983059672cb11794bfd08d591b67b2e15cf6b074b32f0ac00000000");
			return builder;
		}

		protected override NetworkBuilder CreateTestnet()
		{
			var builder = new NetworkBuilder();
			builder.SetConsensus(new Consensus()
			{
				SubsidyHalvingInterval = 100000,
				MajorityEnforceBlockUpgrade = 501,
				MajorityRejectBlockOutdated = 750,
				MajorityWindow = 1000,
				PowLimit = new Target(new uint256("00000fffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")),
				// pre-post-digishield https://github.com/shibacoinppc/shibacoin/blob/v1.2.1/src/chainparams.cpp
				PowTargetTimespan = TimeSpan.FromSeconds(60),
				PowTargetSpacing = TimeSpan.FromSeconds(60),
				PowAllowMinDifficultyBlocks = true,
				CoinbaseMaturity = 240,
				//  Not set in reference client, assuming false
				PowNoRetargeting = false,
				RuleChangeActivationThreshold = 2880,
				MinerConfirmationWindow = 20080,
				LitecoinWorkCalculation = true,
				ConsensusFactory = ShibaConsensusFactory.Instance,
				SupportSegwit = false
			})
			.SetBase58Bytes(Base58Type.PUBKEY_ADDRESS, new byte[] { 113 })
			.SetBase58Bytes(Base58Type.SCRIPT_ADDRESS, new byte[] { 196 })
			.SetBase58Bytes(Base58Type.SECRET_KEY, new byte[] { 241 })
			.SetBase58Bytes(Base58Type.EXT_PUBLIC_KEY, new byte[] { 0x04, 0x35, 0x88, 0xCB })
			.SetBase58Bytes(Base58Type.EXT_SECRET_KEY, new byte[] { 0x04, 0x35, 0x81, 0x95 })
			.SetNetworkStringParser(new DogecoinTestnetAddressStringParser())
			.SetBech32(Bech32Type.WITNESS_PUBKEY_ADDRESS, Encoders.Bech32("tshic"))
			.SetBech32(Bech32Type.WITNESS_SCRIPT_ADDRESS, Encoders.Bech32("tshic"))
			.SetMagic(0xcddac3fa)
			.SetPort(44864)
			.SetRPCPort(44863)
		   .SetName("shic-test")
		   .AddAlias("shic-testnet")
		   .AddAlias("shibacoin-test")
		   .AddAlias("shibacoin-testnet")
		   .SetUriScheme("shibacoin")
		   .AddDNSSeeds(new[]
		   {
				new DNSSeedData("shibacoinshic.org", "testseed.shibacoinshic.org")
		   })
		   .AddSeeds(new NetworkAddress[0])
		   .SetGenesis("010000000000000000000000000000000000000000000000000000000000000000000000450f8ab5cade1c53c2ef36d655076fd0a114378cc54678073b966dff820459e40c845f67f0ff0f1ef98901000101000000010000000000000000000000000000000000000000000000000000000000000000ffffffff3704ffff001d01042f4e617364617120746f20416464204d6963726f537472617465677920746f20746865204e617331303020496e646578ffffffff010058850c0200000043410404721c4861d9047841a25fb469f98ba09e8c9134a4e0ebfb5c84f5e6969e35911d39e492dc2dda8dc84983059672cb11794bfd08d591b67b2e15cf6b074b32f0ac00000000");
			return builder;
		}

		protected override NetworkBuilder CreateRegtest()
		{
			var builder = new NetworkBuilder();
			builder.SetConsensus(new Consensus()
			{
				SubsidyHalvingInterval = 150,
				MajorityEnforceBlockUpgrade = 750,
				MajorityRejectBlockOutdated = 950,
				MajorityWindow = 1000,
				PowLimit = new Target(new uint256("00000fffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")),
				PowTargetTimespan = TimeSpan.FromSeconds(4 * 60 * 60),
				PowTargetSpacing = TimeSpan.FromSeconds(60),
				PowAllowMinDifficultyBlocks = false,
				CoinbaseMaturity = 60,
				//  Not set in reference client, assuming false
				PowNoRetargeting = false,
				RuleChangeActivationThreshold = 540,
				MinerConfirmationWindow = 720,
				LitecoinWorkCalculation = true,
				ConsensusFactory = ShibaConsensusFactory.Instance,
				SupportSegwit = false
			})
			.SetBase58Bytes(Base58Type.PUBKEY_ADDRESS, new byte[] { 111 })
			.SetBase58Bytes(Base58Type.SCRIPT_ADDRESS, new byte[] { 196 })
			.SetBase58Bytes(Base58Type.SECRET_KEY, new byte[] { 239 })
			.SetBase58Bytes(Base58Type.EXT_PUBLIC_KEY, new byte[] { 0x04, 0x35, 0x84, 0xCD })
			.SetBase58Bytes(Base58Type.EXT_SECRET_KEY, new byte[] { 0x04, 0x35, 0x82, 0x97 })
			.SetBech32(Bech32Type.WITNESS_PUBKEY_ADDRESS, Encoders.Bech32("tshic"))
			.SetBech32(Bech32Type.WITNESS_SCRIPT_ADDRESS, Encoders.Bech32("tshic"))
			.SetMagic(0xdcb3bdfc)
			.SetPort(18444)
			.SetRPCPort(18443) // by default this is assigned dynamically, adding port I got for testing
			.SetName("shic-reg")
			.AddAlias("shic-regtest")
			.AddAlias("shibacoin-regtest")
			.AddAlias("shibacoin-reg")
			.SetUriScheme("shibacoin")
			.AddDNSSeeds(new DNSSeedData[0])
			.AddSeeds(new NetworkAddress[0])
			.SetGenesis("010000000000000000000000000000000000000000000000000000000000000000000000696ad20e2dd4365c7459b4a4a5af743d5e92c6da3229e6532cd605f6533f2a5bdae5494dffff7f20020000000101000000010000000000000000000000000000000000000000000000000000000000000000ffffffff1004ffff001d0104084e696e746f6e646fffffffff010058850c020000004341040184710fa689ad5023690c80f3a49c8f13f8d45b8c857fbcbc8bc4a8e4d3eb4b10f4d4604fa08dce601aaf0f470216fe1b51850b4acf21b179c45070ac7b03a9ac00000000");
			return builder;
		}

		protected override void PostInit()
		{
			RegisterDefaultCookiePath("Shibacoin");
		}

	}
}
