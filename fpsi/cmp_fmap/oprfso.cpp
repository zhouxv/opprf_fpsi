
#include "oprfso.h"

namespace CmpFuzzyPSI{

    
    Proto OprfsoSender::setUp(u64 receiverSize, PRNG& prng, Socket& chl, u64 mNumThreads){
        mAltModWPrfSender.mUseMod2F4Ot = 1;
        ole.init(chl.fork(), prng, 0, 1, 1 << 18, 1);

        AltModPrf dm(prng.get());
        std::vector<oc::block> rk(AltModPrf::KeySize);
		for (u64 i = 0; i < AltModPrf::KeySize; ++i)
		{
			rk[i] = oc::block(i, *oc::BitIterator((u8*)&dm.mExpandedKey, i));
		}

        mAltModWPrfSender.init(receiverSize, ole, AltModPrfKeyMode::SenderOnly, AltModPrfInputMode::ReceiverOnly, dm.getKey(), rk);

        // std::cout << "eeeeeee" <<  std::endl;
        // coproto::sync_wait(ole.start());

        co_return;
    }

    Proto OprfsoReceiver::setUp(u64 receiverSize, PRNG& prng, Socket& chl, u64 mNumThreads){
        mAltModWPrfReceiver.mUseMod2F4Ot = 1;
        ole.init(chl.fork(), prng, 1, 1, 1 << 18, 1);

		std::vector<std::array<oc::block, 2>> sk(AltModPrf::KeySize);
		for (u64 i = 0; i < AltModPrf::KeySize; ++i)
		{
			sk[i][0] = oc::block(i, 0);
			sk[i][1] = oc::block(i, 1);
		}     

        mAltModWPrfReceiver.init(receiverSize, ole, AltModPrfKeyMode::SenderOnly, AltModPrfInputMode::ReceiverOnly, {}, sk);

        // std::cout << "eeeeeee" <<  std::endl;
        // coproto::sync_wait(ole.start());

        co_return;
    }

    Proto OprfsoSender::oprfSo(span<oc::block> oprfShare, PRNG& prng, Socket& chl, u64 mNumThreads){
        // std::cout << "eeeeeee" <<  std::endl;
        // coproto::sync_wait(mAltModWPrfSender.evaluate({}, oprfShare, chl, prng));
        auto r = coproto::sync_wait(coproto::when_all_ready(
            mAltModWPrfSender.evaluate({}, oprfShare, chl, prng),
            ole.start()
        ));

        std::get<0>(r).result();
        std::get<1>(r).result();
        // auto r = coproto::sync_wait(coproto::when_all_ready(
        //     ole.start() | macoro::start_on(pool),
        //     sender.evaluate({}, y0, chl_main, prng) | macoro::start_on(pool)
        // ));
        // std::get<0>(r).result();  // ole
        // std::get<1>(r).result();

        co_return;

    }

    Proto OprfsoReceiver::oprfSo(span<oc::block> data, span<oc::block> oprfShare, PRNG& prng, Socket& chl, u64 mNumThreads){
        // DEBUG_LOG("Sender done.");
        // DEBUG_LOG("input length: " << data.size() << " share size: " << oprfShare.size());
        // std::cout << "eeeeeee" <<  std::endl;
        // coproto::sync_wait(mAltModWPrfReceiver.evaluate(data, oprfShare, chl, prng));
        auto r = coproto::sync_wait(coproto::when_all_ready(
            mAltModWPrfReceiver.evaluate(data, oprfShare, chl, prng),
            ole.start()
        ));

        std::get<0>(r).result();
        std::get<1>(r).result();
        
        co_return;
    }

}