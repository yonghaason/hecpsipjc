#include "Pso_Tests.h"
#include "volePSI/Defines.h"
#include "volePSI/Cpso.h"
#include "volePSI/UInt84.h"

#include "cryptoTools/Network/IOService.h"
#include "cryptoTools/Network/Session.h"
#include "cryptoTools/Circuit/BetaLibrary.h"
#include "Common.h"
#include "coproto/Socket/LocalAsyncSock.h"
#include "coproto/Socket/AsioSocket.h"

using namespace std;
using namespace volePSI;
using namespace oc;

void Pso_innerprod_32_test(const oc::CLP &cmd)
{
	PsoSender sender;
	PsoReceiver recver;

	Timer timer, s, r;

	auto sockets = cp::AsioSocket::makePair();
	
	u64 n = cmd.getOr("n", 1ull << cmd.getOr("nn", 10));
	u64 nt = cmd.getOr("nt", 1);

	recver.init(n, n, 0, 40, block(0, 0), nt);
	sender.init(n, n, 0, 40, block(0, 1), nt);
	
	std::random_device rd;
	std::default_random_engine gen(rd());
	std::uniform_int_distribution<u64> dis;

	recver.setTimer(r);
	sender.setTimer(s);
	
	PRNG prng(block(dis(gen), dis(gen)));

	std::vector<block> senderSet(n);
	std::vector<int32_t> senderValue(n);
	std::vector<block> receiverSet(n);
	std::vector<int32_t> receiverValue(n);
	prng.get(senderSet.data(), n);
	// prng.get(senderValue.data(), n);

	for (u64 i = 0; i < n; ++i) 
	{
		senderValue[i] = i;
		receiverValue[i] = -i;
	}

	receiverSet = senderSet;

	int32_t expip = 0;
	int32_t intersection = 0;
	for (u64 i = 0; i < n; ++i)
	{
			if (prng.getBit())
			{
					senderSet[i] = prng.get();
			}
			else {
				intersection += 1;
				expip += senderValue[i] * receiverValue[i];
			}
	}

	int32_t innerprod;	

	auto wallBegin = std::chrono::steady_clock::now();
	auto p0 = sender.setup(sockets[0]);
	auto p1 = recver.setup(sockets[1]);

	timer.setTimePoint("start");
	r.setTimePoint("start");
	s.setTimePoint("start");

	eval(p0, p1);
	auto setupEnd = std::chrono::steady_clock::now();

	u64 setupComm = sockets[0].bytesSent() + sockets[1].bytesSent();

	std::cout << "Setup Comm: " 
			<< " = " << static_cast<double>(setupComm) / (1 << 20)
			<< " MB" << std::endl;

	p0 = sender.sendInnerProd(senderSet, senderValue, sockets[0]);
	p1 = recver.receiveInnerProd(receiverSet, receiverValue, innerprod, sockets[1]);

	eval(p0, p1);
	auto wallEnd = std::chrono::steady_clock::now();

	timer.setTimePoint("end");

	auto totalComm = sockets[0].bytesSent() + sockets[1].bytesSent();
	auto onlineComm = totalComm - setupComm;

	std::cout << "Online Comm: " 
			<< " = " << static_cast<double>(onlineComm) / (1 << 20)
			<< " MB" << std::endl;
	std::cout << "VOLEPSI_INNERPRODUCT_PERF n=" << n
			<< " nt=" << nt
			<< " setupBytes=" << setupComm
			<< " onlineBytes=" << onlineComm
			<< " totalBytes=" << totalComm
			<< " setupSeconds=" << std::chrono::duration<double>(setupEnd - wallBegin).count()
			<< " onlineSeconds=" << std::chrono::duration<double>(wallEnd - setupEnd).count()
			<< " totalSeconds=" << std::chrono::duration<double>(wallEnd - wallBegin).count()
			<< std::endl;

	std::cout << timer << std::endl;
	std::cout <<"Sender Timer\n" << s << "\nReceiver Timer\n" << r << std::endl;

	// std::cout << sum << " / " << toBlock(intersection*2) << std::endl;

	if (innerprod != expip)
		throw RTE_LOC;
}

void Pso_innerprod_84_test(const oc::CLP &cmd)
{
	PsoSender sender;
	PsoReceiver recver;

	Timer timer, s, r;

	auto sockets = cp::AsioSocket::makePair();
	
	u64 n = cmd.getOr("n", 1ull << cmd.getOr("nn", 10));
	u64 nt = cmd.getOr("nt", 1);
    if (n == 0 || n > (1ull << 20)) throw std::invalid_argument("integer bound: 0 < n <= 2^20");
    auto intersectionSize = cmd.isSet("identical") ? n : cmd.getOr("intersection", n/2);
    if (intersectionSize > n) throw std::invalid_argument("intersection > n");

	recver.init(n, n, 0, 40, block(0, 0), nt);
	sender.init(n, n, 0, 40, block(0, 1), nt);
	
	std::random_device rd;
	std::default_random_engine gen(rd());
	std::uniform_int_distribution<u64> dis;

	recver.setTimer(r);
	sender.setTimer(s);
	
	PRNG prng(block(0x12345678, 0x9abcdef0));

	std::vector<block> senderSet(n);
	std::vector<PsoSender::Wide> senderValue(n);
	std::vector<block> receiverSet(n);
	std::vector<PsoSender::Wide> receiverValue(n);
	prng.get(senderSet.data(), n);
	// prng.get(senderValue.data(), n);

	for (u64 i = 0; i < n; ++i) 
	{
		auto dy = cmd.isSet("maxPayload") ? 0xffffffffull : (i * 2654435761ull + 0x9e3779b9ull) & 0xffffffffull;
        auto dx = cmd.isSet("maxPayload") ? 0xffffffffull : (i * 40503ull + 0x7f4a7c15ull) & 0xffffffffull;
        if (cmd.isSet("zeroPayload")) dy = dx = 0;
        senderValue[i] = store84(dy);
        receiverValue[i] = store84(dx);
	}

    prng.get(receiverSet.data(), n);
    UInt128 expectedInteger = 0;
    for (u64 i=0; i<intersectionSize; ++i) {
        receiverSet[n-1-i] = senderSet[i];
        expectedInteger += load84(senderValue[i].data()) * load84(receiverValue[n-1-i].data());
    }

	PsoSender::Wide innerprod{};

	auto wallBegin = std::chrono::steady_clock::now();
	auto p0 = sender.setup(sockets[0]);
	auto p1 = recver.setup(sockets[1]);

	timer.setTimePoint("start");
	r.setTimePoint("start");
	s.setTimePoint("start");

	eval(p0, p1);
	auto setupEnd = std::chrono::steady_clock::now();

	u64 setupComm = sockets[0].bytesSent() + sockets[1].bytesSent();

	std::cout << "Setup Comm: " 
			<< " = " << static_cast<double>(setupComm) / (1 << 20)
			<< " MB" << std::endl;

	p0 = sender.sendInnerProdWide(senderSet, senderValue, sockets[0]);
	p1 = recver.receiveInnerProdWide(receiverSet, receiverValue, innerprod, sockets[1]);

	eval(p0, p1);
	auto wallEnd = std::chrono::steady_clock::now();

	timer.setTimePoint("end");

	auto totalComm = sockets[0].bytesSent() + sockets[1].bytesSent();
	auto onlineComm = totalComm - setupComm;

	std::cout << "Online Comm: " 
			<< " = " << static_cast<double>(onlineComm) / (1 << 20)
			<< " MB" << std::endl;
	std::cout << "VOLEPSI_INNERPRODUCT84_PERF n=" << n
			<< " nt=" << nt
			<< " setupBytes=" << setupComm
			<< " onlineBytes=" << onlineComm
			<< " totalBytes=" << totalComm
			<< " setupSeconds=" << std::chrono::duration<double>(setupEnd - wallBegin).count()
			<< " onlineSeconds=" << std::chrono::duration<double>(wallEnd - setupEnd).count()
			<< " totalSeconds=" << std::chrono::duration<double>(wallEnd - wallBegin).count()
			<< std::endl;

	std::cout << timer << std::endl;
	std::cout <<"Sender Timer\n" << s << "\nReceiver Timer\n" << r << std::endl;

	// std::cout << sum << " / " << toBlock(intersection*2) << std::endl;

    if (load84(innerprod.data()) != expectedInteger)
        throw std::runtime_error("84-bit integer inner product mismatch");
    std::cout << "INTEGER_CORRECT n=" << n << " intersection=" << intersectionSize
              << " maxPayload=" << cmd.isSet("maxPayload") << std::endl;
}
