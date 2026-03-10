# static 
its low responsivness and sensitivity are matched with a very high stability score, it also predicts the least amount of total risk. Very easy to interpret however as it appear linear in nature, you would just say that risk is increasing
# decayed 
Very high responsive and sensitivity as seen in the max and mean change, so predictably not very stable with a autocorrelation of .53. it predicts the third most risk but is very jumpy and doesn't seem to stay anywhere for long. 
# Rolling window
The graph shows rolling window to be fairly consistant with the second lowest max and mean change indicating slow responsivness and weak sensitivity, the autocorrelation is the second highest indicating high stability. For interpretability it seems to be the easiest to read with spike being clear but data expiring makes every spike felt on both sides of the window. 
# kalman filter
very responsive with a max change of .85 and a mean change of .32 indicating high sensitivity as well. In the graph the kalman filter consistantly peaks first before other methods. The autocorrelation is almost riduculusly low sitting around .03, this indicate a very unstable model. It accounts very heavily for the emphemeral nature of IP addresses and just how quickly risk can appear and disappear
# EWMA
with a mean change of .46 it reacts relitivly quickly, with a max change third amoung the methods. The method is also middle of the pack in sensitivity with an average change of .16. its autocorrelation was around .71 which is hihg indicating a very stable algorithm 
# Winner 
The winner of this test in my eyes is the rolling window summation, becasue it stays stable throughout the test, when all other models were rapidly changing. The one downside of the model is that it takes a little while to respond and wind up to a full window, but after that it performs very well. Using AUC to measure aggregated risk it has the second of the highest of the group at an 87, but for a spikey scenario I think that makes sense.