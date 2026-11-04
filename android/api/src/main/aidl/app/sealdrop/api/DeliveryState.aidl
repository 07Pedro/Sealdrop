package app.sealdrop.api;

// state: Sealdrop.STATE_*; time: when it was picked up (4, 5) or failed (6), otherwise 0.
parcelable DeliveryState { String delivery; int state; long time; }
