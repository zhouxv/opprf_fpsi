#include "fmap.h"
#include <unordered_map>

namespace CmpFuzzyPSI
{
    
    inline auto eval(cp::task<> &t0, cp::task<> &t1) {
        auto r = cp::sync_wait(cp::when_all_ready(std::move(t0), std::move(t1)));
        std::get<0>(r).result();
        std::get<1>(r).result();
    }

    oc::block computeBlock(const oc::block& input, u64 mDelta) {
        __uint128_t input_val = *(__uint128_t*)&input;
        __uint128_t delta_val = static_cast<__uint128_t>(mDelta);
        
        if (2 * delta_val == 0) {
            return oc::block(0);
        }

        __uint128_t result_val;
        if (input_val >= delta_val)
            result_val = (input_val - delta_val) / (2 * delta_val);
        else
            result_val = 0;

        oc::block result;
        memcpy(&result, &result_val, sizeof(oc::block));
        return result;
    }

    oc::block computeCell(const oc::block& input, u64 mDelta) {
        __uint128_t input_val = *(__uint128_t*)&input;
        __uint128_t delta_val = static_cast<__uint128_t>(mDelta);
        
        if (2 * delta_val == 0) {
            return oc::block(0);
        }
        __uint128_t result_val = (input_val) / (2 * delta_val);

        oc::block result;
        memcpy(&result, &result_val, sizeof(oc::block));
        return result;
    }

    oc::block leftEndPoint(const oc::block& input, u64 mDelta) {
        __uint128_t input_val = *(__uint128_t*)&input;
        __uint128_t delta_val = static_cast<__uint128_t>(mDelta);
        
        if (2 * delta_val == 0) {
            return oc::block(0);
        }
        __uint128_t result_val = input_val * (2 * delta_val);

        oc::block result;
        memcpy(&result, &result_val, sizeof(oc::block));
        return result;
    }

    oc::block blockSub(const oc::block& input0, const oc::block& input1) {
        __uint128_t input_0 = *(__uint128_t*)&input0;
        __uint128_t input_1 = *(__uint128_t*)&input1;
        
        __uint128_t result_val = input_0 - input_1;

        oc::block result;
        memcpy(&result, &result_val, sizeof(oc::block));
        return result;
    }

    Proto FmapSender::setUp(u64 senderSize, u64 receiverSize, u64 dim, u64 delta, u64 LorH, PRNG& prng, Socket& chl, u64 mNumThreads){
        mSenderSize = senderSize;
        mRecverSize = receiverSize;
        mDim = dim;
        mDelta = delta;
        mLorH = LorH;

        orgSize = osuCrypto::log2ceil(mDelta * 2 * (mSenderSize+2));

        // toBeAdded
        //random VOLE instances
        u64 numVole = senderSize + receiverSize;
        // MultType mulType = DefaultMultType;
        // SdNoiseDistribution noiseType = SdNoiseDistribution::Regular;
        // SilentSecType malType = SilentSecType::SemiHonest;
        // SilentBaseType baseType = SilentBaseType::BaseExtend;
        SilentVoleSender<block, block> sender1;
        SilentVoleReceiver<block, block> receiver2;

        AlignedUnVector<block> A(numVole);
        AlignedUnVector<block> D(numVole);
        AlignedUnVector<block> C(numVole);
        block B_DELTA = prng.get();

        sender1.configure(numVole, SilentBaseType::Base);
        receiver2.configure(numVole, SilentBaseType::Base);

        macoro::sync_wait(sender1.genSilentBaseOts(prng, chl, B_DELTA));
        macoro::sync_wait(receiver2.genSilentBaseOts(prng, chl));

        macoro::sync_wait(sender1.silentSend(B_DELTA, D, prng, chl));
        macoro::sync_wait(receiver2.silentReceive(A, C, prng, chl));

        sMask.resize(senderSize + receiverSize);
        sMask_share.resize(senderSize + receiverSize);
        rMask_share.resize(senderSize + receiverSize);

        sScalar = B_DELTA;
        rMask_share.assign(D.begin(), D.end());
        sMask.assign(A.begin(), A.end());
        sMask_share.assign(C.begin(), C.end());

        //OKVS 1
        auto hashingSeed = block{};
        auto type = PaxosParam::GF128;
        hashingSeed = prng.get();
		mPaxos.init(2 * mRecverSize * mDim, 1 << 14, 3, 40, type, hashingSeed);
		macoro::sync_wait(chl.send(std::move(hashingSeed)));

        //OPRF-so 1
        macoro::sync_wait(mOprfsoSender_0.setUp(mRecverSize * mDim, prng, chl, 1));
        prfKey = mOprfsoSender_0.mAltModWPrfSender.getKey();

        //OKVS 2
        macoro::sync_wait(chl.recv(paxos.mSeed));
		paxos.init(2 * mSenderSize * mDim, 1 << 14, 3, 40, type, paxos.mSeed);

        //OPRF-so 1
        macoro::sync_wait(mOprfsoReceiver_1.setUp(mSenderSize * mDim, prng, chl));

        co_return;
    }

    Proto FmapReceiver::setUp(u64 senderSize, u64 receiverSize, u64 dim, u64 delta, u64 LorH, PRNG& prng, Socket& chl, u64 mNumThreads){
        mSenderSize = senderSize;
        mRecverSize = receiverSize;
        mDim = dim;
        mDelta = delta;
        mLorH = LorH;

        orgSize = osuCrypto::log2ceil(mDelta * 2 * (mSenderSize+2));

        //random VOLE instances, toBeAdded
        u64 numVole = senderSize + receiverSize;
        // MultType mulType = DefaultMultType;
        // SdNoiseDistribution noiseType = SdNoiseDistribution::Regular;
        // SilentSecType malType = SilentSecType::SemiHonest;
        // SilentBaseType baseType = SilentBaseType::BaseExtend;
        SilentVoleSender<block, block> sender2;
        SilentVoleReceiver<block, block> receiver1;

        AlignedUnVector<block> A(numVole);
        AlignedUnVector<block> D(numVole);
        AlignedUnVector<block> C(numVole);
        block B_DELTA = prng.get();

        receiver1.configure(numVole, SilentBaseType::Base);
        sender2.configure(numVole, SilentBaseType::Base);

        macoro::sync_wait(receiver1.genSilentBaseOts(prng, chl));
        macoro::sync_wait(sender2.genSilentBaseOts(prng, chl, B_DELTA));

        macoro::sync_wait(receiver1.silentReceive(A, C, prng, chl));
        macoro::sync_wait(sender2.silentSend(B_DELTA, D, prng, chl));

        rMask.resize(senderSize + receiverSize);
        rMask_share.resize(senderSize + receiverSize);
        sMask_share.resize(senderSize + receiverSize);

        rScalar = B_DELTA;
        sMask_share.assign(D.begin(), D.end());
        rMask.assign(A.begin(), A.end());
        rMask_share.assign(C.begin(), C.end());

        //OKVS1
        auto type = PaxosParam::GF128;
        macoro::sync_wait(chl.recv(paxos.mSeed));
		paxos.init(2 * mRecverSize * mDim, 1 << 14, 3, 40, type, paxos.mSeed);

        //OPRF-so 1
        macoro::sync_wait(mOprfsoReceiver_0.setUp(mRecverSize * mDim, prng, chl));

        //OKVS 2
        auto hashingSeed = block{};
        hashingSeed = prng.get();
		mPaxos.init(2 * mSenderSize * mDim, 1 << 14, 3, 40, type, hashingSeed);
		macoro::sync_wait(chl.send(std::move(hashingSeed)));

        //OPRF-so 2
        macoro::sync_wait(mOprfsoSender_1.setUp(mSenderSize * mDim, prng, chl, 1));
        prfKey = mOprfsoSender_1.mAltModWPrfSender.getKey();;

        co_return;
    }

    Proto FmapSender::fuzzyMap(span<block> inputs, span<block> Identifiers, span<block> oringins, PRNG& prng, Socket& chl, u64 mNumThreads){

        std::vector<block> mAssignments(2*mSenderSize*mDim);
        std::vector<block> blocksContainInputs(2*mSenderSize*mDim);
        std::vector<block> mIdentifiers(mSenderSize, ZeroBlock);
        getID(inputs, mIdentifiers, blocksContainInputs, mAssignments, oringins, prng);

        //Compute ID of receiver
        //send OKVS
		std::vector<block> mOKVS(mPaxos.size());
        mPaxos.solve<block>(blocksContainInputs, mAssignments, mOKVS, &prng, mNumThreads);
        macoro::sync_wait(chl.send(std::move(mOKVS)));
        //OPRF-so, sends vole mask
        std::vector<block> oprfShare_0(mRecverSize*mDim);
        macoro::sync_wait(mOprfsoSender_0.oprfSo(oprfShare_0, prng, chl));
        std::vector<block> oprfShare_0_sum(mRecverSize, oc::ZeroBlock);
        for(u64 i=0; i<mRecverSize; i++){
            for (u64 j=0; j<mDim; j++){
                oprfShare_0_sum[i] ^= oprfShare_0[i*mDim+j];
            }
            oprfShare_0_sum[i] ^= sMask[i]; // the first mRecverSize instances of VOLE
        }
        macoro::sync_wait(chl.send(std::move(oprfShare_0_sum)));
        //receive encrptied IDs and decrypt and send back
        std::vector<block> encryID_rec(mRecverSize);
        macoro::sync_wait(chl.recv(encryID_rec));
        for(u64 i=0; i<mRecverSize; i++){
            encryID_rec[i] = sScalar.gf128Mul(encryID_rec[i] ^ sMask_share[i]) ^ rMask_share[i];
        }
        macoro::sync_wait(chl.send(std::move(encryID_rec)));
        //Receiver ID computed


        //Compute ID of Sender
        //Compute blocks
        std::vector<block> blocksOfInputs(mSenderSize*mDim);
        for (u64 i=0; i<mSenderSize*mDim; i++){
            blocksOfInputs[i] = computeBlock(inputs[i], mDelta);
            blocksOfInputs[i] = block(i % mDim, 0) ^ blocksOfInputs[i];
        }

        //receive OKVS and decode
        std::vector<block> decodeVal(mSenderSize*mDim);
        std::vector<block> recvOKVS(paxos.size());
		macoro::sync_wait(chl.recv(recvOKVS));
        paxos.mAddToDecode = true;
        paxos.decode<block>(blocksOfInputs, decodeVal, recvOKVS, mNumThreads);
        //OPRF-so and receive VOLE mask, compute vole later
        std::vector<block> oprfShare_1(mSenderSize*mDim);
        macoro::sync_wait(mOprfsoReceiver_1.oprfSo(blocksOfInputs, oprfShare_1, prng, chl));
        std::vector<block> oprfShare_1_sum(mSenderSize);
        macoro::sync_wait(chl.recv(oprfShare_1_sum)); // the last mSenderSize instances of VOLE
        //compute encrptied IDs
        std::vector<block> encryID(mSenderSize, oc::ZeroBlock);
        for(u64 i=0; i<mSenderSize; i++){
            oprfShare_1_sum[i] = sScalar.gf128Mul(oprfShare_1_sum[i]) ^ rMask_share[i + mRecverSize];
            for (u64 j=0; j<mDim; j++){
                encryID[i] ^= decodeVal[i*mDim+j];
                oprfShare_1_sum[i] ^= sScalar.gf128Mul(oprfShare_1[i*mDim+j]);
            }
            encryID[i] = sScalar.gf128Mul(encryID[i] ^ mIdentifiers[i]) ^ oprfShare_1_sum[i] ^ sMask[i + mRecverSize];
        }
        macoro::sync_wait(chl.send(std::move(encryID)));
        std::vector<block> maskedID(mSenderSize);
        macoro::sync_wait(chl.recv(maskedID));
        for(u64 i=0; i<mSenderSize; i++){
            Identifiers[i] = maskedID[i] ^ sMask_share[i + mRecverSize];
        }
        //Sender ID computed
            
        // block rScalar;
        // std::vector<block> rID(mRecverSize);
        // std::vector<block> rMask(mSenderSize + mRecverSize);
        // std::vector<block> rMask_share0(mSenderSize + mRecverSize);
        // std::vector<block> rBlocks(mRecverSize*mDim);
        // std::vector<block> mAssignments_s(2*mRecverSize*mDim);
        // std::vector<block> blocksContainInputs_s(2*mRecverSize*mDim);
        // std::vector<block> oprfShare_1_s(mSenderSize*mDim);
        // AltModPrf::KeyType prfKey_s;

        // macoro::sync_wait(chl.recv(rScalar));
        // macoro::sync_wait(chl.recv(rID));
        // macoro::sync_wait(chl.recv(rMask));
        // macoro::sync_wait(chl.recv(rMask_share0));
        // macoro::sync_wait(chl.recv(rBlocks));
        // macoro::sync_wait(chl.recv(blocksContainInputs_s));
        // macoro::sync_wait(chl.recv(mAssignments_s));
        // macoro::sync_wait(chl.recv(oprfShare_1_s));
        // macoro::sync_wait(chl.recv(prfKey_s));

        // block scalar = sScalar.gf128Mul(rScalar);

        // VOLE check
        // for (u64 i=0; i<5; i++){
        //     if (sScalar.gf128Mul(rMask[i]) != (rMask_share0[i]^rMask_share[i]))
        //         std::cout << i << "wrong! " << std::endl;
        // }

        // PRF check
        // AltModPrf prf_s;
        // prf_s.setKey(prfKey_s);
        // for (u64 i=0; i<mSenderSize*mDim; i++){
        //     if (prf_s.eval(blocksOfInputs[i]) != (oprfShare_1_s[i] ^ oprfShare_1[i]))
        //         std::cout << "wrong: " << i << std::endl;
        // }

        // Deciding check
        // std::vector<block> encryIDtmp(mSenderSize, oc::ZeroBlock);
        // AltModPrf prf_s;
        // prf_s.setKey(prfKey_s);
        // for(u64 i=0; i<5; i++){
        //     for (u64 j=0; j<mDim; j++){
        //         encryIDtmp[i] ^= (decodeVal[i*mDim+j] ^ prf_s.eval(blocksOfInputs[i*mDim+j]));
        //         std::cout << i*mDim+j << " " << blocksOfInputs[i*mDim+j] << " " << (decodeVal[i*mDim+j] ^ prf_s.eval(blocksOfInputs[i*mDim+j])) << std::endl;
        //     }
        //     // std::cout << i << " " << encryIDtmp[i] << " " << rID[i] << std::endl;
        //     // if (encryIDtmp[i] == rID[i]){
        //     //     std::cout << "correct: " << i << std::endl;
        //     // }
        // }

        // for (u64 i=0; i<5; i++){
        //     std::cout << i << ": " << scalar.gf128Mul(rID[i] ^ mIdentifiers[i]) << std::endl;
        // }

        // std::cout << "points 0: " << computeBlock(inputs[1], mDelta) << " " << computeCell(inputs[1], mDelta) << 
        // " " << computeCell(inputs[1], mDelta).sub_epi64(OneBlock) << std::endl;
        
        // for (u64 i=0; i<2*mSenderSize*mDim; i++){
        //     for (u64 j=0; j < 5*mDim; j++){
        //         if (mAssignments_s[i] == decodeVal[j])
        //             std::cout << "block of" << j << ": " << i << std::endl;
        //         if (blocksContainInputs_s[i] == blocksOfInputs[j])
        //             std::cout << "block of" << j << ": " << i << std::endl;
        //     }
        // }
        

        co_await chl.flush();
        co_return;
    }

    Proto FmapReceiver::fuzzyMap(span<block> inputs, span<block> Identifiers, PRNG& prng, Socket& chl, u64 mNumThreads){
        std::vector<block> mAssignments(2*mRecverSize*mDim);
        std::vector<block> blocksContainInputs(2*mRecverSize*mDim);
        std::vector<block> mIdentifiers(mRecverSize, ZeroBlock);
        getID(inputs, mIdentifiers, blocksContainInputs, mAssignments, prng);


        //Compute ID of receiver
        //Compute blocks
        std::vector<block> blocksOfInputs(mRecverSize*mDim);
        for (u64 i=0; i<mRecverSize*mDim; i++){
            blocksOfInputs[i] = computeBlock(inputs[i], mDelta);
            blocksOfInputs[i] = block(i % mDim, 0) ^ blocksOfInputs[i];
            // blocksOfInputs[i] = _mm_set_epi64x(i % mDim, ((u64*)&blocksOfInputs[i])[0]);
        }
        //receive OKVS and decode
        std::vector<block> decodeVal(mRecverSize*mDim);
        std::vector<block> recvOKVS(paxos.size());
		macoro::sync_wait(chl.recv(recvOKVS));
        paxos.mAddToDecode = true;
        paxos.decode<block>(blocksOfInputs, decodeVal, recvOKVS, mNumThreads);
        //OPRF-so and receive VOLE mask, compute vole later
        std::vector<block> oprfShare_0(mRecverSize*mDim);
        macoro::sync_wait(mOprfsoReceiver_0.oprfSo(blocksOfInputs, oprfShare_0, prng, chl));
        std::vector<block> oprfShare_0_sum(mRecverSize);
        macoro::sync_wait(chl.recv(oprfShare_0_sum)); // the first mRecverSize instances of VOLE
        //compute encrptied IDs
        std::vector<block> encryID(mRecverSize, oc::ZeroBlock);
        for(u64 i=0; i<mRecverSize; i++){
            oprfShare_0_sum[i] = rScalar.gf128Mul(oprfShare_0_sum[i]) ^ sMask_share[i];
            for (u64 j=0; j<mDim; j++){
                encryID[i] ^= decodeVal[i*mDim+j];
                oprfShare_0_sum[i] ^= rScalar.gf128Mul(oprfShare_0[i*mDim+j]);
            }
            encryID[i] = rScalar.gf128Mul(encryID[i]^mIdentifiers[i]) ^ oprfShare_0_sum[i] ^ rMask[i];
        }
        macoro::sync_wait(chl.send(std::move(encryID)));
        std::vector<block> maskedID(mRecverSize);
        macoro::sync_wait(chl.recv(maskedID));
        for(u64 i=0; i<mRecverSize; i++){
            Identifiers[i] = maskedID[i] ^ rMask_share[i];
        }
        //Receiver ID computed


        //Compute ID of sender
        //send OKVS
		std::vector<block> mOKVS(mPaxos.size());
        mPaxos.solve<block>(blocksContainInputs, mAssignments, mOKVS, &prng, mNumThreads);
        macoro::sync_wait(chl.send(std::move(mOKVS)));
        //OPRF-so, sends vole mask
        std::vector<block> oprfShare_1(mSenderSize*mDim);
        macoro::sync_wait(mOprfsoSender_1.oprfSo(oprfShare_1, prng, chl));
        std::vector<block> oprfShare_1_sum(mSenderSize, oc::ZeroBlock);
        for(u64 i=0; i<mSenderSize; i++){
            for (u64 j=0; j<mDim; j++){
                oprfShare_1_sum[i] ^= oprfShare_1[i*mDim+j];
            }
            oprfShare_1_sum[i] ^= rMask[i + mRecverSize]; // the last mSenderSize instances of VOLE
        }
        macoro::sync_wait(chl.send(std::move(oprfShare_1_sum)));
        //receive encrptied IDs and decrypt and send back
        std::vector<block> encryID_rec(mSenderSize);
        macoro::sync_wait(chl.recv(encryID_rec));
        for(u64 i=0; i<mSenderSize; i++){
            encryID_rec[i] = rScalar.gf128Mul(encryID_rec[i] ^ rMask_share[i + mRecverSize]) ^ sMask_share[i + mRecverSize];
        }
        macoro::sync_wait(chl.send(std::move(encryID_rec)));
        //Receiver ID computed

        // macoro::sync_wait(chl.send(rScalar));
        // macoro::sync_wait(chl.send(mIdentifiers));
        // macoro::sync_wait(chl.send(rMask));
        // macoro::sync_wait(chl.send(rMask_share));
        // macoro::sync_wait(chl.send(blocksOfInputs));
        // macoro::sync_wait(chl.send(blocksContainInputs));
        // macoro::sync_wait(chl.send(mAssignments));
        // macoro::sync_wait(chl.send(oprfShare_1));
        // macoro::sync_wait(chl.send(prfKey));


        co_await chl.flush();
        co_return;
    }

    void FmapSender::getID(span<block> inputs, span<block> mIdentifiers, span<block> blocksContainInputs, span<block> mAssignments, span<block> oringins, PRNG& prng){
        AltModPrf dm;
        dm.setKey(prfKey);
        u64 idx = 0;

        prng.get(blocksContainInputs.data(), blocksContainInputs.size());
        prng.get(mAssignments.data(), mAssignments.size());
        for (u64 i=0; i < mDim; i++){
            std::unordered_map<block, block> blocks_check;
            for (u64 j=0; j < mSenderSize; j++){
                block block1 = computeCell(inputs[j*mDim+i], mDelta);
                block block0;
                if (block1 != ZeroBlock)
                    block0 = block1.sub_epi64(OneBlock);
                else
                    block0 = ZeroBlock;
                block random;
                if(blocks_check.find(block0) != blocks_check.end()){
                    if (blocks_check.find(block1) != blocks_check.end()){
                        random = blocks_check[block0];
                        block tmp = block1;
                        while (blocks_check.find(tmp) != blocks_check.end() && blocks_check[tmp]!=random){
                            blocks_check[tmp] = random;
                            tmp = tmp.add_epi64(OneBlock);
                        }
                    } else {
                        random = blocks_check[block0];
                        blocks_check.insert({block1, blocks_check[block0]});
                    }
                } else if (blocks_check.find(block1) != blocks_check.end()){
                    random = blocks_check[block1];
                    blocks_check.insert({block0, blocks_check[block1]});
                } else {
                    random = prng.get();
                    blocks_check.emplace(block0, random);
                    blocks_check.emplace(block1, random);
                }
                mIdentifiers[j] ^= random;
            }
            //fill OKVS key-value
            for (const auto& kv : blocks_check) {
                blocksContainInputs[idx] = block(i, 0) ^ kv.first;
                // blocksContainInputs[idx] = _mm_set_epi64x(i, ((u64*)&kv.first)[0]);
                mAssignments[idx] = kv.second ^ dm.eval(blocksContainInputs[idx]);
                idx++;
                // if (idx++ >= mSenderSize)
                //     break;
            }
            // generate oringins
            for (u64 j=0; j < mSenderSize; j++){
                block block0 = computeCell(inputs[j*mDim+i], mDelta);
                block tmp = block0;
                while (blocks_check.find(tmp) != blocks_check.end()){
                    if (tmp == ZeroBlock){
                        tmp = tmp.sub_epi64(OneBlock);
                        break;
                    }
                    tmp = tmp.sub_epi64(OneBlock);
                }
                oringins[j*mDim+i] = leftEndPoint(tmp.add_epi64(OneBlock), mDelta);

                // if (j<5)
                //     std::cout << j*mDim+i << " " << inputs[j*mDim+i] << " " << oringins[j*mDim+i] << " " <<
                //     blockSub(inputs[j*mDim+i], oringins[j*mDim+i]) << std::endl;
            }
        }

    }

    void FmapReceiver::getID(span<block> inputs, span<block> mIdentifiers, span<block> blocksContainInputs, span<block> mAssignments, PRNG& prng){
        AltModPrf dm;
        dm.setKey(prfKey); // costly!
        u64 idx = 0;

        prng.get(blocksContainInputs.data(), blocksContainInputs.size());
        prng.get(mAssignments.data(), mAssignments.size());
        for (u64 i=0; i < mDim; i++){
            std::unordered_map<block, block> blocks_check;
            for (u64 j=0; j < mRecverSize; j++){
                block block1 = computeCell(inputs[j*mDim+i], mDelta);
                block block0;
                if (block1 != ZeroBlock)
                    block0 = block1.sub_epi64(OneBlock);
                else
                    block0 = ZeroBlock;
                block random;
                if(blocks_check.find(block0) != blocks_check.end()){
                    if (blocks_check.find(block1) != blocks_check.end()){
                        random = blocks_check[block0];
                        block tmp = block1;
                        while (blocks_check.find(tmp) != blocks_check.end() && blocks_check[tmp]!=random){
                            blocks_check[tmp] = random;
                            tmp = tmp.add_epi64(OneBlock);
                        }
                    } else {
                        random = blocks_check[block0];
                        blocks_check.insert({block1, blocks_check[block0]});
                    }
                } else if (blocks_check.find(block1) != blocks_check.end()){
                    random = blocks_check[block1];
                    blocks_check.insert({block0, blocks_check[block1]});
                } else {
                    random = prng.get();
                    blocks_check.emplace(block0, random);
                    blocks_check.emplace(block1, random);
                }
                mIdentifiers[j] ^= random;

                // if (j<5){
                //     std::cout << j*mDim+i << " " << (block1^block(i, 0)) << " " << (block0^block(i, 0)) << " " << (random)<< std::endl;
                //     // std::cout << j << " " << mIdentifiers[j] << std::endl;
                // }
            }
            
            // fill OKVS key-value
            for (const auto& kv : blocks_check) {
                blocksContainInputs[idx] = block(i, 0) ^ kv.first;
                mAssignments[idx] = kv.second ^ dm.eval(blocksContainInputs[idx]);
                idx++;
                // if (idx++ >= mRecverSize)
                //     break;
            }
        }

    }

}