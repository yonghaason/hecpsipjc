#include "Cpso.h"
#include "volePSI/GMW/Gmw.h"

#include <bitset>

#include <sstream>

namespace volePSI
{
    Proto PsoSender::sendInnerProd(span<block> Y, span<int32_t> data, Socket& chl)
    {
        MC_BEGIN(Proto, this, Y, data, &chl,
                 s = RsCpsiReceiver::Sharing{},
                 cpsiReceiver = std::make_unique<RsCpsiReceiver>(),
                 clearShares = std::vector<int32_t>{},
                 innerProdShare = int32_t{},
                 invMapping = std::vector<u64>{},
                 reordered_data = std::vector<int32_t>{},

                 rot1Sender = std::make_unique<oc::SilentOtExtSender>(),
                 rot1Msgs = std::vector<std::array<block, 2>>{},
                 ot1Msgs = std::vector<std::array<int32_t, 2>>{},

                 rot2Receiver = std::make_unique<oc::SilentOtExtReceiver>(),
                 rot2Msgs = std::vector<oc::block>{},
                 ot2Msgs = std::vector<std::array<int32_t, 2>>{},
                 
                 msRotReceiver = std::make_unique<oc::SilentOtExtReceiver>(),
                 msRotMsgs = std::vector<oc::block>{},
                 msChoices = oc::BitVector{},
                 msOtMsgs = std::vector<int32_t>{},
                 
                 r = int32_t{},
                 tmp = int32_t{},
                 i = u64{},
                 j = u64{}
                 );

        assert(mSenderSize == Y.size());
        
        comm = chl.bytesSent();
        cpsiReceiver->init(mSenderSize, mRecverSize, sizeof(int32_t), mSsp, mPrng.get(), mNumThreads, ValueShareType::add32);
        if (mSetup) {
            cpsiReceiver->setTriple(mOtFactory.mMult, mOtFactory.mAdd, mOtFactory.mN);
        }
        MC_AWAIT(cpsiReceiver->receive(Y, s, chl));
        setTimePoint("PsoSender::InnerProd::Cpsi receive");

        // Clear out 1st OT 
        rot1Msgs.resize(s.mFlagBits.size());
        rot1Sender->configure(s.mFlagBits.size(), 2, mNumThreads);
        MC_AWAIT(rot1Sender->send(rot1Msgs, mPrng, chl));

        ot1Msgs.resize(s.mFlagBits.size());
        clearShares.resize(s.mFlagBits.size());
        for (i = 0; i < s.mFlagBits.size(); i++)
        {
            r = mPrng.get<int32_t>();
            memcpy(&tmp, s.mValues[i].data(), sizeof(int32_t));
            ot1Msgs[i][s.mFlagBits[i]] = rot1Msgs[i][s.mFlagBits[i]].mData[0] + r;
            ot1Msgs[i][!s.mFlagBits[i]] = rot1Msgs[i][!s.mFlagBits[i]].mData[0] + r + tmp;
            clearShares[i] = -r;
        }
        MC_AWAIT(chl.send(ot1Msgs));
        
        // Clear out 2nd OT 
        rot2Msgs.resize(s.mFlagBits.size());
        rot2Receiver->configure(s.mFlagBits.size(), 2, mNumThreads);
        MC_AWAIT(rot2Receiver->receive(s.mFlagBits, rot2Msgs, mPrng, chl));

        ot2Msgs.resize(s.mFlagBits.size());
        MC_AWAIT(chl.recv(ot2Msgs));

        for (i = 0; i < ot2Msgs.size(); i++) {
            clearShares[i] += ot2Msgs[i][s.mFlagBits[i]] - rot2Msgs[i].mData[0];
        }
        setTimePoint("PsoSender::InnerProd::Clear out");

        // MultShare
        invMapping.resize(s.mFlagBits.size(), ~u64(0));
        for (i = 0; i < Y.size(); i++) {
            invMapping[s.mMapping[i]] = i;
        }

        tmp = 0;
        reordered_data.resize(s.mFlagBits.size());
        for (i = 0; i < s.mFlagBits.size(); i++) 
        {   
            if (invMapping[i] != ~u64(0)) {
                reordered_data[i] = (data[invMapping[i]]);
            }
            else {
                reordered_data[i] = tmp;
            }
        }
        msChoices = oc::BitVector((u8*) reordered_data.data(), s.mFlagBits.size() * 32);
        
        msRotMsgs.resize(msChoices.size());
        msRotReceiver->configure(msChoices.size(), 2, mNumThreads);
        MC_AWAIT(msRotReceiver->receive(msChoices, msRotMsgs, mPrng, chl));

        setTimePoint("PsoSender::InnerProd::Multshare-setup");

        msOtMsgs.resize(msChoices.size());
        MC_AWAIT(chl.recv(msOtMsgs));

        innerProdShare = 0;
        for (i = 0; i < s.mFlagBits.size(); i++)
        {   
            if (invMapping[i] != ~u64(0))
                innerProdShare += clearShares[i] * data[invMapping[i]];
            
            for (j = 0; j < 32; j++)
            {
                if (msChoices[32*i + j])
                    innerProdShare += msOtMsgs[32*i + j] - msRotMsgs[32*i + j].mData[0];
                else 
                    innerProdShare += msRotMsgs[32*i + j].mData[0];
            }
        }
        MC_AWAIT(chl.send(innerProdShare));
        setTimePoint("PsoSender::InnerProd::MultShare");

        // comm = chl.bytesSent() - comm;
        // commexp = (u64) cardByteLength * s.mFlagBits.size();
        // std::cout << "PsoSender::OT = " << comm << " bytes / expected: " << commexp << " bytes" << std::endl;

        MC_END();
    }

    Proto PsoReceiver::receiveInnerProd(span<block> X, span<int32_t> data, int32_t& innerProd, Socket& chl)
    {
        MC_BEGIN(Proto, this, X, data, &innerProd, &chl,
                 s = RsCpsiSender::Sharing{},
                 cpsiSender = std::make_unique<RsCpsiSender>(),
                 dataInMatrix = oc::Matrix<u8>{},
                 clearShares = std::vector<int32_t>{},
                 innerProdShare = int32_t{},
                 innerProdShareTheir = int32_t{},

                 rot1Receiver = std::make_unique<oc::SilentOtExtReceiver>(),
                 rot1Msgs = std::vector<oc::block>{},
                 ot1Msgs = std::vector<std::array<int32_t, 2>>{},

                 rot2Sender = std::make_unique<oc::SilentOtExtSender>(),
                 rot2Msgs = std::vector<std::array<block, 2>>{},
                 ot2Msgs = std::vector<std::array<int32_t, 2>>{},

                 msRotSender = std::make_unique<oc::SilentOtExtSender>(),
                 msRotMsgs = std::vector<std::array<block, 2>>{},
                 msOtMsgs = std::vector<int32_t>{},
                 
                 r = int32_t{},
                 tmp = int32_t{},
                 i = u64{},
                 j = u64{}
                );
        assert(mReceiverSize == X.size());

        comm = chl.bytesSent();
        // if (mTimer) {
        //     cpsiSender->setTimer(*mTimer);
        // }
        dataInMatrix.resize(X.size(), sizeof(int32_t));
        std::memcpy(dataInMatrix.data(), (u8*) data.data(), X.size() * sizeof(int32_t));

        cpsiSender->init(mSenderSize, mRecverSize, sizeof(int32_t), mSsp, mPrng.get(), mNumThreads, ValueShareType::add32);
        if (mSetup) {
            cpsiSender->setTriple(mOtFactory.mMult, mOtFactory.mAdd, mOtFactory.mN);
        }
        MC_AWAIT(cpsiSender->send(X, dataInMatrix, s, chl));
        setTimePoint("PsoReceiver::InnerProd::Cpsi send");

        // Clear out 1st OT 
        rot1Msgs.resize(s.mFlagBits.size());
        rot1Receiver->configure(s.mFlagBits.size(), 2, mNumThreads);
        MC_AWAIT(rot1Receiver->receive(s.mFlagBits, rot1Msgs, mPrng, chl));

        clearShares.resize(s.mFlagBits.size());
        ot1Msgs.resize(s.mFlagBits.size());
        MC_AWAIT(chl.recv(ot1Msgs));

        for (i = 0; i < ot1Msgs.size(); i++) {
            clearShares[i] = ot1Msgs[i][s.mFlagBits[i]] - rot1Msgs[i].mData[0];
        }

        // Clear out 2nd OT 
        rot2Msgs.resize(s.mFlagBits.size());
        rot2Sender->configure(s.mFlagBits.size(), 2, mNumThreads);
        MC_AWAIT(rot2Sender->send(rot2Msgs, mPrng, chl));

        ot2Msgs.resize(s.mFlagBits.size());

        for (i = 0; i < s.mFlagBits.size(); i++)
        {
            r = mPrng.get<int32_t>();
            memcpy(&tmp, s.mValues[i].data(), sizeof(int32_t));
            ot2Msgs[i][s.mFlagBits[i]] = rot2Msgs[i][s.mFlagBits[i]].mData[0] + r;
            ot2Msgs[i][!s.mFlagBits[i]] = rot2Msgs[i][!s.mFlagBits[i]].mData[0] + r + tmp;
            clearShares[i] -= r;
        }

        MC_AWAIT(chl.send(ot2Msgs));

        setTimePoint("PsoReceiver::InnerProd::Clear out");

        // MultShare
        msRotMsgs.resize(s.mFlagBits.size() * 32);
        msRotSender->configure(s.mFlagBits.size() * 32, 2, mNumThreads);
        MC_AWAIT(msRotSender->send(msRotMsgs, mPrng, chl));

        setTimePoint("PsoReceiver::InnerProd::Multshare-setup");
        
        innerProdShare = 0;
        msOtMsgs.resize(s.mFlagBits.size() * 32);
        for (i = 0; i < s.mFlagBits.size(); i++)
        {
            for (j = 0; j < 32; j++)
            {
                msOtMsgs[32*i + j] = msRotMsgs[32*i + j][0].mData[0] + msRotMsgs[32*i + j][1].mData[0] + (clearShares[i] << j);
                innerProdShare -= msRotMsgs[32*i + j][0].mData[0];
            }
        }
        MC_AWAIT(chl.send(msOtMsgs));

        MC_AWAIT(chl.recv(innerProdShareTheir));
        innerProd = innerProdShare + innerProdShareTheir;
        setTimePoint("PsoReceiver::InnerProd::MultShare");

        // comm = chl.bytesSent() - comm;
        // commexp = 0;
        // std::cout << "PsoReceiver::FinalOT = " << comm << " bytes / expected: " << commexp << " bytes" << std::endl;

        MC_END();
    }


    // ---- 11-byte XOR helpers for the 84-bit width cost harness ----
    namespace {
        using Wide = std::array<u8, 11>;
        using u128w = unsigned __int128;
        inline Wide operator^(const Wide& a, const Wide& b){ Wide r; for(int i=0;i<11;i++) r[i]=a[i]^b[i]; return r; }
        inline Wide wTrunc(const block& k){ Wide r; std::memcpy(r.data(), &k, 11); return r; }
        inline Wide wShl(const Wide& a, u64 j){
            u128w v=0; std::memcpy(&v,a.data(),11); v<<=j; v&=(((u128w)1<<84)-1);
            Wide r; std::memcpy(r.data(),&v,11); return r; }
        // 84 choice bits per item packed contiguously: an 11-byte item holds 88 bits, use its low 84
        inline oc::BitVector wBits(const std::vector<Wide>& v){ oc::BitVector bv(v.size()*84); for(u64 i=0;i<v.size();i++) for(u64 j=0;j<84;j++) bv[i*84+j] = (v[i][j/8]>>(j%8))&1; return bv; }
        inline Wide wMul(const Wide& a, const Wide& b){
            u128w x=0,y=0,acc=0; std::memcpy(&x,a.data(),11); std::memcpy(&y,b.data(),11);
            for(int i=0;i<84;i++) if((y>>i)&1) acc^=(x<<i);
            acc&=(((u128w)1<<84)-1); Wide r; std::memcpy(r.data(),&acc,11); return r; }
    }

    Proto PsoSender::sendInnerProdWide(span<block> Y, span<Wide> data, Socket& chl)
    {
        MC_BEGIN(Proto, this, Y, data, &chl,
                 s = RsCpsiReceiver::Sharing{},
                 cpsiReceiver = std::make_unique<RsCpsiReceiver>(),
                 clearShares = std::vector<Wide>{},
                 innerProdShare = Wide{},
                 invMapping = std::vector<u64>{},
                 reordered_data = std::vector<Wide>{},

                 rot1Sender = std::make_unique<oc::SilentOtExtSender>(),
                 rot1Msgs = std::vector<std::array<block, 2>>{},
                 ot1Msgs = std::vector<std::array<Wide, 2>>{},

                 rot2Receiver = std::make_unique<oc::SilentOtExtReceiver>(),
                 rot2Msgs = std::vector<oc::block>{},
                 ot2Msgs = std::vector<std::array<Wide, 2>>{},
                 
                 msRotReceiver = std::make_unique<oc::SilentOtExtReceiver>(),
                 msRotMsgs = std::vector<oc::block>{},
                 msChoices = oc::BitVector{},
                 msOtMsgs = std::vector<Wide>{},
                 
                 r = Wide{},
                 tmp = Wide{},
                 i = u64{},
                 j = u64{}
                 );

        assert(mSenderSize == Y.size());
        
        comm = chl.bytesSent();
        cpsiReceiver->init(mSenderSize, mRecverSize, sizeof(Wide), mSsp, mPrng.get(), mNumThreads, ValueShareType::Xor);
        if (mSetup) {
            cpsiReceiver->setTriple(mOtFactory.mMult, mOtFactory.mAdd, mOtFactory.mN);
        }
        MC_AWAIT(cpsiReceiver->receive(Y, s, chl));
        setTimePoint("PsoSender::InnerProd::Cpsi receive");

        // Clear out 1st OT 
        rot1Msgs.resize(s.mFlagBits.size());
        rot1Sender->configure(s.mFlagBits.size(), 2, mNumThreads);
        MC_AWAIT(rot1Sender->send(rot1Msgs, mPrng, chl));

        ot1Msgs.resize(s.mFlagBits.size());
        clearShares.resize(s.mFlagBits.size());
        for (i = 0; i < s.mFlagBits.size(); i++)
        {
            r = mPrng.get<Wide>();
            memcpy(&tmp, s.mValues[i].data(), sizeof(Wide));
            ot1Msgs[i][s.mFlagBits[i]] = wTrunc(rot1Msgs[i][s.mFlagBits[i]]) ^ r;
            ot1Msgs[i][!s.mFlagBits[i]] = wTrunc(rot1Msgs[i][!s.mFlagBits[i]]) ^ r ^ tmp;
            clearShares[i] = r;
        }
        MC_AWAIT(chl.send(ot1Msgs));
        
        // Clear out 2nd OT 
        rot2Msgs.resize(s.mFlagBits.size());
        rot2Receiver->configure(s.mFlagBits.size(), 2, mNumThreads);
        MC_AWAIT(rot2Receiver->receive(s.mFlagBits, rot2Msgs, mPrng, chl));

        ot2Msgs.resize(s.mFlagBits.size());
        MC_AWAIT(chl.recv(ot2Msgs));

        for (i = 0; i < ot2Msgs.size(); i++) {
            clearShares[i] = clearShares[i] ^ ot2Msgs[i][s.mFlagBits[i]] ^ wTrunc(rot2Msgs[i]);
        }
        setTimePoint("PsoSender::InnerProd::Clear out");

        // MultShare
        invMapping.resize(s.mFlagBits.size(), ~u64(0));
        for (i = 0; i < Y.size(); i++) {
            invMapping[s.mMapping[i]] = i;
        }

        tmp = Wide{};
        reordered_data.resize(s.mFlagBits.size());
        for (i = 0; i < s.mFlagBits.size(); i++) 
        {   
            if (invMapping[i] != ~u64(0)) {
                reordered_data[i] = data[invMapping[i]];
            }
            else {
                reordered_data[i] = tmp;
            }
        }
        msChoices = wBits(reordered_data);
        
        msRotMsgs.resize(msChoices.size());
        msRotReceiver->configure(msChoices.size(), 2, mNumThreads);
        MC_AWAIT(msRotReceiver->receive(msChoices, msRotMsgs, mPrng, chl));

        setTimePoint("PsoSender::InnerProd::Multshare-setup");

        msOtMsgs.resize(msChoices.size());
        MC_AWAIT(chl.recv(msOtMsgs));

        innerProdShare = Wide{};
        for (i = 0; i < s.mFlagBits.size(); i++)
        {   
            if (invMapping[i] != ~u64(0))
                innerProdShare = innerProdShare ^ wMul(clearShares[i], data[invMapping[i]]);
            
            for (j = 0; j < 84; j++)
            {
                if (msChoices[84*i + j])
                    innerProdShare = innerProdShare ^ msOtMsgs[84*i + j] ^ wTrunc(msRotMsgs[84*i + j]);
                else 
                    innerProdShare = innerProdShare ^ wTrunc(msRotMsgs[84*i + j]);
            }
        }
        MC_AWAIT(chl.send(innerProdShare));
        setTimePoint("PsoSender::InnerProd::MultShare");

        // comm = chl.bytesSent() - comm;
        // commexp = (u64) cardByteLength * s.mFlagBits.size();
        // std::cout << "PsoSender::OT = " << comm << " bytes / expected: " << commexp << " bytes" << std::endl;

        MC_END();
    }

    Proto PsoReceiver::receiveInnerProdWide(span<block> X, span<Wide> data, Wide& innerProd, Socket& chl)
    {
        MC_BEGIN(Proto, this, X, data, &innerProd, &chl,
                 s = RsCpsiSender::Sharing{},
                 cpsiSender = std::make_unique<RsCpsiSender>(),
                 dataInMatrix = oc::Matrix<u8>{},
                 clearShares = std::vector<Wide>{},
                 innerProdShare = Wide{},
                 innerProdShareTheir = Wide{},

                 rot1Receiver = std::make_unique<oc::SilentOtExtReceiver>(),
                 rot1Msgs = std::vector<oc::block>{},
                 ot1Msgs = std::vector<std::array<Wide, 2>>{},

                 rot2Sender = std::make_unique<oc::SilentOtExtSender>(),
                 rot2Msgs = std::vector<std::array<block, 2>>{},
                 ot2Msgs = std::vector<std::array<Wide, 2>>{},

                 msRotSender = std::make_unique<oc::SilentOtExtSender>(),
                 msRotMsgs = std::vector<std::array<block, 2>>{},
                 msOtMsgs = std::vector<Wide>{},
                 
                 r = Wide{},
                 tmp = Wide{},
                 i = u64{},
                 j = u64{}
                );
        assert(mReceiverSize == X.size());

        comm = chl.bytesSent();
        // if (mTimer) {
        //     cpsiSender->setTimer(*mTimer);
        // }
        dataInMatrix.resize(X.size(), sizeof(Wide));
        std::memcpy(dataInMatrix.data(), (u8*) data.data(), X.size() * sizeof(Wide));

        cpsiSender->init(mSenderSize, mRecverSize, sizeof(Wide), mSsp, mPrng.get(), mNumThreads, ValueShareType::Xor);
        if (mSetup) {
            cpsiSender->setTriple(mOtFactory.mMult, mOtFactory.mAdd, mOtFactory.mN);
        }
        MC_AWAIT(cpsiSender->send(X, dataInMatrix, s, chl));
        setTimePoint("PsoReceiver::InnerProd::Cpsi send");

        // Clear out 1st OT 
        rot1Msgs.resize(s.mFlagBits.size());
        rot1Receiver->configure(s.mFlagBits.size(), 2, mNumThreads);
        MC_AWAIT(rot1Receiver->receive(s.mFlagBits, rot1Msgs, mPrng, chl));

        clearShares.resize(s.mFlagBits.size());
        ot1Msgs.resize(s.mFlagBits.size());
        MC_AWAIT(chl.recv(ot1Msgs));

        for (i = 0; i < ot1Msgs.size(); i++) {
            clearShares[i] = ot1Msgs[i][s.mFlagBits[i]] ^ wTrunc(rot1Msgs[i]);
        }

        // Clear out 2nd OT 
        rot2Msgs.resize(s.mFlagBits.size());
        rot2Sender->configure(s.mFlagBits.size(), 2, mNumThreads);
        MC_AWAIT(rot2Sender->send(rot2Msgs, mPrng, chl));

        ot2Msgs.resize(s.mFlagBits.size());

        for (i = 0; i < s.mFlagBits.size(); i++)
        {
            r = mPrng.get<Wide>();
            memcpy(&tmp, s.mValues[i].data(), sizeof(Wide));
            ot2Msgs[i][s.mFlagBits[i]] = wTrunc(rot2Msgs[i][s.mFlagBits[i]]) ^ r;
            ot2Msgs[i][!s.mFlagBits[i]] = wTrunc(rot2Msgs[i][!s.mFlagBits[i]]) ^ r ^ tmp;
            clearShares[i] = clearShares[i] ^ r;
        }

        MC_AWAIT(chl.send(ot2Msgs));

        setTimePoint("PsoReceiver::InnerProd::Clear out");

        // MultShare
        msRotMsgs.resize(s.mFlagBits.size() * 84);
        msRotSender->configure(s.mFlagBits.size() * 84, 2, mNumThreads);
        MC_AWAIT(msRotSender->send(msRotMsgs, mPrng, chl));

        setTimePoint("PsoReceiver::InnerProd::Multshare-setup");
        
        innerProdShare = Wide{};
        msOtMsgs.resize(s.mFlagBits.size() * 84);
        for (i = 0; i < s.mFlagBits.size(); i++)
        {
            for (j = 0; j < 84; j++)
            {
                msOtMsgs[84*i + j] = wTrunc(msRotMsgs[84*i + j][0]) ^ wTrunc(msRotMsgs[84*i + j][1]) ^ wShl(clearShares[i], j);
                innerProdShare = innerProdShare ^ wTrunc(msRotMsgs[84*i + j][0]);
            }
        }
        MC_AWAIT(chl.send(msOtMsgs));

        MC_AWAIT(chl.recv(innerProdShareTheir));
        innerProd = innerProdShare ^ innerProdShareTheir;
        setTimePoint("PsoReceiver::InnerProd::MultShare");

        // comm = chl.bytesSent() - comm;
        // commexp = 0;
        // std::cout << "PsoReceiver::FinalOT = " << comm << " bytes / expected: " << commexp << " bytes" << std::endl;

        MC_END();
    }

}
