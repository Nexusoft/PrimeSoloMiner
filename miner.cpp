#include "core.h"

unsigned int nBestHeight = 0;
unsigned int nStartTimer = 0;

unsigned int nPrimes = 0;
unsigned int nChains = 0;
unsigned int nSieves = 0;
unsigned int nBlocks = 0;


unsigned int nDifficulty   = 0;


namespace Core
{

	/** Main Miner Thread. Bound to the class with boost. Might take some rearranging to get working with OpenCL. **/
	void MinerThread::PrimeMiner()
	{
		loop
		{
			try
			{
				/** Keep thread at idle CPU usage if waiting to submit or recieve block. **/
				Sleep(1);
				
				/** Assure that this thread stays idle when waiting for new block, or share submission. **/
				if(fNewBlock || fBlockWaiting)
					continue;
				
				/** Lock the Thread at this Mutex when Changing Block Pointer. **/
				MUTEX.lock();
				CBigNum BaseHash(cBlock.GetHash());
				MUTEX.unlock();
				
				mpz_t zPrimeOrigin, zPrimeOriginOffset, zFirstSieveElement, zPrimorialMod, zTempVar, zResidue, zTwo, zN, zOctuplet;
				unsigned int i = 0;
				unsigned int j = 0;
				unsigned int nSize = 0;
				unsigned int nPrimeCount = 0;
				unsigned int nSieveDifficulty = 0;
				uint64 nStart = 0;
				uint64 nStop = 0;
				unsigned int nLastOffset = 0;

				long nElapsedTime = 0;
				long nStartTime = 0;
				mpz_init(zPrimeOriginOffset);
				mpz_init(zFirstSieveElement);
				mpz_init(zPrimorialMod);
				mpz_init(zOctuplet);
				mpz_init(zTempVar);
				mpz_init(zPrimeOrigin);
				mpz_init(zResidue);
				mpz_init_set_ui(zTwo, 2);
				mpz_init(zN);

				bignum2mpz(&BaseHash, zPrimeOrigin);
				nSize = mpz_sizeinbase(zPrimeOrigin, 2);
				unsigned char* bit_array_sieve = (unsigned char*)malloc((nBitArray_Size)/8);
				for(j=0; j<256 && !fNewBlock && !fBlockWaiting; j++)
				{
					memset(bit_array_sieve, 0x00, (nBitArray_Size)/8);

					mpz_mod(zPrimorialMod, zPrimeOrigin, zPrimorial);
					mpz_sub(zPrimorialMod, zPrimorial, zPrimorialMod);

					mpz_mod(zPrimorialMod, zPrimorialMod, zPrimorial);
					
					mpz_import( zOctuplet, 1, 1, sizeof(octuplet_origins[j]), 0, 0, &octuplet_origins[j]);
					mpz_add(zPrimorialMod, zPrimorialMod, zOctuplet);
					
					mpz_add(zTempVar, zPrimeOrigin, zPrimorialMod);

					mpz_set(zFirstSieveElement, zTempVar);

					for(unsigned int i=nPrimorialEndPrime; i<nPrimeLimit && !fNewBlock && !fBlockWaiting; i++)
					{
						unsigned long  p = primes[i];
						unsigned int inv = inverses[i];
						unsigned int base_remainder = mpz_tdiv_ui(zTempVar, p);

						unsigned int remainder = base_remainder;
						unsigned long r = (p-remainder)*inv;
						unsigned int index = r % p;
						while(index < nBitArray_Size)
						{
							bit_array_sieve[(index)>>3] |= (1<<((index)&7));
							index += p;
						}
						
						remainder = base_remainder + 2;
						if (p<remainder)
							remainder -= p;
						r = (p-remainder)*inv;
						index = r % p;
						while(index < nBitArray_Size)
						{
							bit_array_sieve[(index)>>3] |= (1<<((index)&7));
							index += p;
						}

						remainder = base_remainder + 6;
						if (p<remainder)
							remainder -= p;
						r = (p-remainder)*inv;
						index = r % p;
						while(index < nBitArray_Size)
						{
							bit_array_sieve[(index)>>3] |= (1<<((index)&7));
							index += p;
						}

						remainder = base_remainder + 8;
						if (p<remainder)
							remainder -= p;
						r = (p - remainder) * inv;
						index = r % p;
						while(index < nBitArray_Size)
						{
								bit_array_sieve[(index)>>3] |= (1<<((index)&7));
							index += p;
						}
						
						remainder = base_remainder + 12;
						if (p<remainder)
							remainder -= p;
						r = (p - remainder) * inv;
						index = r % p;
						while(index < nBitArray_Size)
						{
							bit_array_sieve[(index)>>3] |= (1<<((index)&7));
							index += p;
						}
						
						nSieves++;
					}

					for(i=0; i<nBitArray_Size && !fNewBlock && !fBlockWaiting; i++)
					{
						if( bit_array_sieve[(i)>>3] & (1<<((i)&7)) )
							continue;
							
						/** Get the Prime origin from Primorial and Sieve. **/
						mpz_mul_ui(zTempVar, zPrimorial, i);
						mpz_add(zTempVar, zFirstSieveElement, zTempVar);
						mpz_set(zPrimeOriginOffset, zTempVar);

						
						/** Ensure Number is Prime before Checking Cluster. **/
						mpz_sub_ui(zN, zTempVar, 1);
						mpz_powm(zResidue, zTwo, zN, zTempVar);
						if (mpz_cmp_ui(zResidue, 1) != 0)
							continue;
						
						nPrimes++;
						
						
						nPrimeCount = 1;
						nLastOffset = 2;
						unsigned int nPrimeGap = 2;

						
						/** Determine with GMP the size of possible cluster at this prime. **/
						while(nPrimeGap <= 12)
						{
							mpz_add_ui(zTempVar, zTempVar, 2);
							
							mpz_sub_ui(zN, zTempVar, 1);
							mpz_powm(zResidue, zTwo, zN, zTempVar);
							if (mpz_cmp_ui(zResidue, 1) == 0)
							{
								nPrimeGap = 2;
								nPrimeCount++;
								nPrimes++;
							}
							else
								nPrimeGap  += 2;
								
							nLastOffset+=2;
						}
						

						if(nPrimeCount >= 3)
						{	
							/** Increment the Chain Counter if Cluster is above size 3. **/
							nChains++;
							
							/** Obtain the nNonce value from the Temporary mpz. **/
							mpz_sub(zTempVar, zPrimeOriginOffset, zPrimeOrigin);
							cBlock.nNonce = mpz2uint64(zTempVar);
							
							/** Run Small Check from Sieve Before Costly Cluster Check. **/
							if(SetBits(GetSieveDifficulty(cBlock.GetPrime() + nLastOffset, nPrimeCount)) < cBlock.nBits)
								continue;
							
							/** Check that the Prime Cluster is large enough. **/
							std::vector<unsigned int> vPrimes;
							unsigned int nBits = GetPrimeBits(cBlock.GetPrime(), 1, vPrimes);
							if(nBits >= cBlock.nBits)
							{
								printf("[MASTER] Prime Cluster Found of Difficulty %f [", nBits / 10000000.0);
								
								for(int nIndex = 0; nIndex < vPrimes.size() - 1; nIndex++)
									printf(" + %u,", vPrimes[nIndex]);
									
								printf(" + %u ]\n\n%s\n\n", vPrimes[vPrimes.size() - 1], cBlock.GetPrime().ToString().c_str());
								cServerConnection->SubmitBlock(cBlock);

								break;
							}
						}
					}
				}

				mpz_clear(zPrimeOrigin);
				mpz_clear(zPrimeOriginOffset);
				mpz_clear(zFirstSieveElement);
				mpz_clear(zResidue);
				mpz_clear(zTwo);
				mpz_clear(zN);
				mpz_clear(zPrimorialMod);
				mpz_clear(zTempVar);
				mpz_clear(zOctuplet);

				free(bit_array_sieve);
				
				fNewBlock = true;
				fBlockWaiting = false;
			}
			catch(std::exception& e){ printf("ERROR: %s\n", e.what()); }
		}
	}
	

	/** Reset the block on each of the Threads. **/
	void ServerConnection::ResetThreads()
	{
		/** Clear the Submit Queue. **/
		SUBMIT_MUTEX.lock();
		
		while(!SUBMIT_QUEUE.empty())
			SUBMIT_QUEUE.pop();
			
		SUBMIT_MUTEX.unlock();

		
		/** Reset each individual flag to tell threads to stop mining. **/
		for(int nIndex = 0; nIndex < THREADS.size(); nIndex++)
		{
			THREADS[nIndex]->fNewBlock      = true;
			THREADS[nIndex]->fBlockWaiting  = false;
		}
		
		/** Reset the Block Height Timer. **/
		HEIGHT_TIMER.Reset();
	}
	
		
	/** Add a Block to the Submit Queue. **/
	void ServerConnection::SubmitBlock(CBlock cBlock)
	{
		SUBMIT_MUTEX.lock();
		SUBMIT_QUEUE.push(cBlock);
		SUBMIT_MUTEX.unlock();
	}
	
		
	/** Main Connection Thread. Handles all the networking to allow
		Mining threads the most performance. **/
	void ServerConnection::ServerThread()
	{
		
		/** Don't begin until all mining threads are Created. **/
		while(THREADS.size() != nThreads)
			Sleep(1);
				
				
		/** Initialize the Server Connection. **/
		CLIENT = new LLP::Miner(IP, PORT);
			
				
		/** Initialize a Timer for the Hash Meter. **/
		METER_TIMER.Start();
		HEIGHT_TIMER.Start();

		loop
		{
			try
			{
				/** Run this thread at 100 Cycles per Second. **/
				Sleep(10);
					
					
				/** Attempt with best efforts to keep the Connection Alive. **/
				if(!CLIENT->Connected() || CLIENT->Errors() || CLIENT->Timeout(nTimeout))
				{
					ResetThreads();
					
					if(!CLIENT->Connect())
						continue;
					else
					{
						CLIENT->SetChannel(1);
						CLIENT->GetHeight();
					}
				}
				
				
				/** Check the Block Height every Second. **/
				if(HEIGHT_TIMER.ElapsedMilliseconds() > 1000)
				{
					HEIGHT_TIMER.Reset();
					CLIENT->GetHeight();
				}
				
				
				/** Show the Meter every 15 Seconds. **/
				if(METER_TIMER.Elapsed() > 15)
				{
					unsigned int SecondsElapsed = (unsigned int)time(0) - nStartTimer;
					unsigned int nElapsed = METER_TIMER.Elapsed();
					double PPS = (double) nPrimes / nElapsed;
					double CPS = (double) nChains / nElapsed;
					double CSD = (double) (nBlocks * 60.0) / (SecondsElapsed / 60.0);
					
					nPrimes = 0;
					nChains = 0;
					
					printf("[METERS] %f PPS | %f CPS | %u Blocks | %f CSD per Hour | Height = %u | Difficulty %f | %02d:%02d:%02d\n", PPS, CPS, nBlocks, CSD, nBestHeight, nDifficulty / 10000000.0, (SecondsElapsed/3600)%60, (SecondsElapsed/60)%60, (SecondsElapsed)%60);
					METER_TIMER.Reset();	
				}
					
					
				/** Submit any Shares from the Mining Threads. **/
				SUBMIT_MUTEX.lock();
				while(SUBMIT_QUEUE.size() > 0)
				{
					CBlock cBlock = SUBMIT_QUEUE.front();
					SUBMIT_QUEUE.pop();
					
					CLIENT->SubmitBlock(cBlock.hashMerkleRoot, cBlock.nNonce);
					RESPONSE_QUEUE.push(cBlock);
				}
				SUBMIT_MUTEX.unlock();
				
				
				/** Check if there is work to do for each Miner Thread. **/
				for(int nIndex = 0; nIndex < THREADS.size(); nIndex++)
				{
					/** Attempt to get a new block from the Server if Thread needs One. **/
					if(THREADS[nIndex]->fNewBlock)
					{
						CLIENT->GetBlock();
						THREADS[nIndex]->fBlockWaiting = true;
						THREADS[nIndex]->fNewBlock = false;
					}
				}
					
				CLIENT->ReadPacket();
				if(!CLIENT->PacketComplete())
					continue;
						
				/** Handle the New Packet, and Interpret its Data. **/
				LLP::Packet PACKET = CLIENT->NewPacket();
				CLIENT->ResetPacket();
							
							
				/** Output if a Share is Accepted. **/
				if(PACKET.HEADER == CLIENT->GOOD)
				{
					if(RESPONSE_QUEUE.empty())
						continue;
						
					CBlock cResponse = RESPONSE_QUEUE.front();
					RESPONSE_QUEUE.pop();
					
					nBlocks++;
					printf("[MASTER] Block Accepted by Coinshield Network\n");
				}
					
					
				/** Output if a Share is Rejected. **/
				else if(PACKET.HEADER == CLIENT->FAIL) 
				{
					if(RESPONSE_QUEUE.empty())
						continue;
						
					CBlock cResponse = RESPONSE_QUEUE.front();
					RESPONSE_QUEUE.pop();
					
					printf("[MASTER] Block Rejected by Coinshield Network\n");
				}
					
				/** Reset the Threads if a New Block came in. **/
				else if(PACKET.HEADER == CLIENT->BLOCK_HEIGHT)
				{
					unsigned int nHeight = bytes2uint(PACKET.DATA);
					if(nHeight > nBestHeight)
					{
						nBestHeight = nHeight;
						printf("[MASTER] Coinshield Network: New Block %u.\n", nBestHeight);
							
						ResetThreads();
					}
				}
					
					
				/** Set the Block for the Thread if there is a New Block Packet. **/
				else if(PACKET.HEADER == CLIENT->BLOCK_DATA)
				{
					/** Search for a Thread waiting for a New Block to Supply its need. **/
					for(int nIndex = 0; nIndex < THREADS.size(); nIndex++)
					{
						if(THREADS[nIndex]->fBlockWaiting)
						{
							THREADS[nIndex]->MUTEX.lock();
							THREADS[nIndex]->cBlock.nVersion      = bytes2uint(std::vector<unsigned char>(PACKET.DATA.begin(), PACKET.DATA.begin() + 4));
							
							THREADS[nIndex]->cBlock.hashPrevBlock.SetBytes (std::vector<unsigned char>(PACKET.DATA.begin() + 4, PACKET.DATA.begin() + 132));
							THREADS[nIndex]->cBlock.hashMerkleRoot.SetBytes(std::vector<unsigned char>(PACKET.DATA.begin() + 132, PACKET.DATA.end() - 20));
							
							THREADS[nIndex]->cBlock.nChannel      = bytes2uint(std::vector<unsigned char>(PACKET.DATA.end() - 20, PACKET.DATA.end() - 16));
							THREADS[nIndex]->cBlock.nHeight       = bytes2uint(std::vector<unsigned char>(PACKET.DATA.end() - 16, PACKET.DATA.end() - 12));
							THREADS[nIndex]->cBlock.nBits         = bytes2uint(std::vector<unsigned char>(PACKET.DATA.end() - 12,  PACKET.DATA.end() - 8));
							THREADS[nIndex]->cBlock.nNonce        = bytes2uint64(std::vector<unsigned char>(PACKET.DATA.end() - 8,  PACKET.DATA.end()));
							THREADS[nIndex]->MUTEX.unlock();
							
							if(THREADS[nIndex]->cBlock.nHeight < nBestHeight)
							{
								printf("[MASTER] Received Obsolete Block %u... Requesting New Block.\n", THREADS[nIndex]->cBlock.nHeight);
								CLIENT->GetBlock();
									
								break;
							}
							
							/** Set the Difficulty from most recent Block Received. **/
							nDifficulty = THREADS[nIndex]->cBlock.nBits;
								
							printf("[MASTER] Block %s Height = %u Received on Thread %u\n", THREADS[nIndex]->cBlock.GetHash().ToString().substr(0, 20).c_str(), THREADS[nIndex]->cBlock.nHeight, nIndex);
							THREADS[nIndex]->fBlockWaiting = false;
								
							break;
						}
					}
				}
					
			}
			catch(std::exception& e)
			{
				printf("%s\n", e.what()); CLIENT = new LLP::Miner(IP, PORT); 
			}
		}
	}

}

int main(int argc, char *argv[])
{

	if(argc < 3)
	{
		printf("Too Few Arguments. The Required Arguments are 'IP PORT'\n");
		printf("Default Arguments are Total Threads = CPU Cores and Connection Timeout = 10 Seconds\n");
		printf("Format for Arguments is 'IP PORT THREADS TIMEOUT'\n");
		
		Sleep(10000);
		
		return 0;
	}
		
	std::string IP = argv[1];
	std::string PORT = argv[2];
	
	int nThreads = GetTotalCores(), nTimeout = 10;
	
	if(argc > 3)
		nThreads = boost::lexical_cast<int>(argv[3]);
	
	if(argc > 4)
		nTimeout = boost::lexical_cast<int>(argv[4]);
	
	printf("Coinshield Prime Solo Miner 1.0.0 - Created by Videlicet - Optimized by Supercomputing\n");
	printf("The Meter Has 2 Values:\nPPS = Primes Per Second\nCPS = Clusters Per Second [Of larger than 3.x Difficulty]\n\n");
	Sleep(2000);
	
	printf("Initializing Miner %s:%s Threads = %i Timeout = %i\n", IP.c_str(), PORT.c_str(), nThreads, nTimeout);
	
	Core::InitializePrimes();
	nStartTimer = (unsigned int)time(0);
	
	Core::ServerConnection MINERS(IP, PORT, nThreads, nTimeout);
	loop { Sleep(10); }
	
	return 0;
}
