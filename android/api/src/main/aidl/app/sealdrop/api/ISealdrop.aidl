// Sealdrop's interface for apps (docs/PROTOCOL.md §9.1). Bind with the action app.sealdrop.action.DELIVER and the
// package app.sealdrop. Call from a background thread, never from one that matters (such as a recording).
package app.sealdrop.api;

import app.sealdrop.api.AddResult;
import app.sealdrop.api.BeginResult;
import app.sealdrop.api.DeliveryState;
import app.sealdrop.api.FileOffer;
import app.sealdrop.api.SenderInfo;

interface ISealdrop {
    int apiVersion();                                   // 1
    BeginResult begin(String delivery, int network);    // network: 1 = may use mobile data, 2 = Wi-Fi only
    AddResult add(String handle, in FileOffer[] files); // up to 100 files and 1 GiB per call; one larger file alone
    int commit(String handle);                          // checks everything, then queues the delivery
    oneway void abort(String handle);
    oneway void hold(int seconds);                      // the caller's hold; clamped to 1 … 900 seconds
    oneway void release();                              // ends the caller's own hold only
    DeliveryState[] status(in String[] deliveries);     // the caller's own; at most 500 IDs, more gives null
    SenderInfo info();
    int sendNow(boolean allowMobileForWifiOnly);        // the caller's own deliveries; answers 0, 2 or 3
}
