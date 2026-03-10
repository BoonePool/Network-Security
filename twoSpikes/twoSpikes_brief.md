# static
in this scenario the static sum was farily responsive, although it was all the way are .91 it was the lowest max change for the scenario. Its mean change was also very low, indicating a low sensitivity. It was easily the most stable with an autocorrelation at .96.
# decayed 
very responsive with a max change at nearly 1 this indicates an ability to jump from the minimum to the maximum in one day. for sensitivity it ranks third with a mean score of .392 this is probably due to the fact that it gets down to zero pretty fast and has long streches without much movment. as for stability it ranks second to last behind the kalman filter, this is a bit strange as low sensitivity normally corresponds to high stability. 
# rolling window
With an max change of .995 the rolling window has the second lowest score indicating a low responsivness. The mean change is the second highest at .0394 making it a rare example of low responsivness with high sensitivity. Stability wise rolling does well with the second highest at a .9
# kalman filter 
with a responsivness rounded to 1 the kalman filter is incredibly responsive and it also boasts the highest mean change at .0396 this show at very hihg sensitivity and responsivness naturally leading to very little stability as seen in it autocorrelation of only .146. This method is fairly easy to interpret but its spikey nature has little predective quality and is most usefull for understanding the current state. 
# EWMA
EWMA has tended to stay in the middle of the pack well in our tests so far and does agian ranking third in max change and fourth in mean change, indicating some responsiveness but lower than average sensitivity. for stability it boasts a auto correlation of .7085 making it the third most stable by this metric. for interpretibility lets risk degrade slower than the rest making it more ready to handle the second spike. 
# winner 
The winner of this scenario I would say is EWMA is the clear winner due to its stabiliity which makes sense given the somewhat gradual way it increases and deacreases and the way it streches out its risk predection, this leads to a higher overall prediction of risk with an AUC of 4.3 almost doubling kalman and the decayed sum. Crucially in the data aside from the static sum it was the only method that predicted risk before the second spike leading to a better prediction in this dataset. 

