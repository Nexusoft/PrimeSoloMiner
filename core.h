#ifndef COINSHIELD_LLP_CORE_H
#define COINSHIELD_LLP_CORE_H

#include "types.h"
#include <queue>

namespace LLP
{
	class Outbound : public Connection
	{
		Service_t IO_SERVICE;
		std::string IP, PORT;
		
	public:
		/** Outgoing Client Connection Constructor **/
		Outbound(std::string ip, std::string port) : IP(ip), PORT(port), Connection() { }
		
		bool Connect()
		{
			try
			{
				using boost::asio::ip::tcp;
				
				tcp::resolver 			  RESOLVER(IO_SERVICE);
				tcp::resolver::query      QUERY   (tcp::v4(), IP.c_str(), PORT.c_str());
				tcp::resolver::iterator   ADDRESS = RESOLVER.resolve(QUERY);
				
				this->SOCKET = Socket_t(new tcp::socket(IO_SERVICE));
				this->SOCKET -> connect(*ADDRESS, this->ERROR_HANDLE);
				
				if(Errors())
				{
					this->Disconnect();
					
					printf("Failed to Connect to Mining LLP Server...\n");
					return false;
				}
				
				this->CONNECTED = true;
				this->TIMER.Start();
				
				printf("Connected to %s:%s...\n", IP.c_str(), PORT.c_str());

				return true;
			}
			catch(...){ }
			
			this->CONNECTED = false;
			return false;
		}
		
	};
	
	
	class Miner : public Outbound
	{
	public:
		Miner(std::string ip, std::string port) : Outbound(ip, port){}
		
		enum
		{
			/** DATA PACKETS **/
			BLOCK_DATA   = 0,
			SUBMIT_BLOCK = 1,
			BLOCK_HEIGHT = 2,
			SET_CHANNEL  = 3,
					
			/** REQUEST PACKETS **/
			GET_BLOCK    = 129,
			GET_HEIGHT   = 130,
			
			/** RESPONSE PACKETS **/
			GOOD     = 200,
			FAIL     = 201,
					
			/** GENERIC **/
			PING     = 253,
			CLOSE    = 254
		};
		
		
		/** Current Newly Read Packet Access. **/
		inline Packet NewPacket() { return this->INCOMING; }
		
		
		/** Create a Packet with the Given Header. **/
		inline Packet GetPacket(unsigned char HEADER)
		{
			Packet PACKET;
			PACKET.HEADER = HEADER;
			
			return PACKET;
		}
		
		
		/** Get a new Block from the Pool Server. **/
		inline void GetBlock()    { this -> WritePacket(GetPacket(GET_BLOCK));   }
		
		
		/** Get the Current Height of the Coinshield Network. **/
		inline void GetHeight()    { this -> WritePacket(GetPacket(GET_HEIGHT)); }
		
		
		/** Set the Current Channel to Mine for in the LLP. **/
		inline void SetChannel(unsigned int nChannel)
		{
			Packet PACKET = GetPacket(SET_CHANNEL);
			PACKET.LENGTH = 4;
			PACKET.DATA   = uint2bytes(nChannel);
			
			this -> WritePacket(PACKET);  
		}
		
		
		/** Submit a Block to the Coinshield Network. **/
		inline void SubmitBlock(uint512 hashMerkleRoot, uint64 nNonce)
		{
			Packet PACKET = GetPacket(SUBMIT_BLOCK);
			PACKET.DATA = hashMerkleRoot.GetBytes();
			std::vector<unsigned char> NONCE  = uint2bytes64(nNonce);
			
			PACKET.DATA.insert(PACKET.DATA.end(), NONCE.begin(), NONCE.end());
			PACKET.LENGTH = 72;
			
			this -> WritePacket(PACKET);
		}
	};
	
}

namespace Core
{
	class ServerConnection;
	
	extern unsigned int *primes;
	extern unsigned int *inverses;

	extern unsigned int nBitArray_Size;
	extern mpz_t  zPrimorial;

	extern unsigned int prime_limit;
	extern unsigned int nPrimeLimit;
	extern unsigned int nPrimorialEndPrime;

	extern uint64 octuplet_origins[];
	
	void InitializePrimes();
	unsigned int SetBits(double nDiff);
	double GetPrimeDifficulty(CBigNum prime, int checks);
	double GetSieveDifficulty(CBigNum next, unsigned int clusterSize);
	unsigned int GetPrimeBits(CBigNum prime, int checks);
	unsigned int GetFractionalDifficulty(CBigNum composite);
	std::vector<unsigned int> Eratosthenes(int nSieveSize);
	bool DivisorCheck(CBigNum test);
	unsigned long PrimeSieve(CBigNum BaseHash, unsigned int nDifficulty, unsigned int nHeight);
	bool PrimeCheck(CBigNum test, int checks);
	CBigNum FermatTest(CBigNum n, CBigNum a);
	bool Miller_Rabin(CBigNum n, int checks);
	
	
	class CBlock
	{
	public:

		/** Begin of Header.   BEGIN(nVersion) **/
		unsigned int  nVersion;
		uint1024 hashPrevBlock;
		uint512 hashMerkleRoot;
		unsigned int  nChannel;
		unsigned int   nHeight;
		unsigned int     nBits;
		uint64          nNonce;
		/** End of Header.     END(nNonce). 
			All the components to build an SK1024 Block Hash. **/
			
		CBlock()
		{
			nVersion       = 0;
			hashPrevBlock  = 0;
			hashMerkleRoot = 0;
			nChannel       = 0;
			nHeight        = 0;
			nBits          = 0;
			nNonce         = 0;
		}
			
		uint1024 GetHash() const
		{
			return SK1024(BEGIN(nVersion), END(nBits));
		}
		
		CBigNum GetPrime() const
		{
			return CBigNum(GetHash() + nNonce);
		}
	};
	
	
	
	/** Class to hold the basic data a Miner will use to build a Block.
		Used to allow one Connection for any amount of threads. **/
	class MinerThread
	{
	public:
		ServerConnection* cServerConnection;
		
		CBlock cBlock;
		unsigned int nDifficulty;
		
		bool fNewBlock, fBlockWaiting, fBlockFound;
		LLP::Thread_t THREAD;
		boost::mutex MUTEX;
		
		MinerThread(ServerConnection* cConnection) : cServerConnection(cConnection), fNewBlock(true), fBlockWaiting(false), THREAD(boost::bind(&MinerThread::PrimeMiner, this)) { }

		void PrimeMiner();
	};
	
		/** Class to handle all the Connections via Mining LLP.
		Independent of Mining Threads for Higher Efficiency. **/
	class ServerConnection
	{
	public:
		LLP::Miner* CLIENT;
		int nThreads, nTimeout;
		std::vector<MinerThread*> THREADS;
		LLP::Thread_t THREAD;
		LLP::Timer    METER_TIMER;
		LLP::Timer    HEIGHT_TIMER;
		std::string   IP, PORT;
		
		boost::mutex    SUBMIT_MUTEX;

		std::queue<CBlock> SUBMIT_QUEUE;
		std::queue<CBlock> RESPONSE_QUEUE;
		
		ServerConnection(std::string ip, std::string port, int nMaxThreads, int nMaxTimeout) : IP(ip), PORT(port), METER_TIMER(), HEIGHT_TIMER(), nThreads(nMaxThreads), nTimeout(nMaxTimeout), THREAD(boost::bind(&ServerConnection::ServerThread, this))
		{
			for(int nIndex = 0; nIndex < nThreads; nIndex++)
				THREADS.push_back(new MinerThread(this));
		}
		
		/** Reset the block on each of the Threads. **/
		void ResetThreads();
		void SubmitBlock(CBlock cBlock);
		void ServerThread();

	};
}



#endif
