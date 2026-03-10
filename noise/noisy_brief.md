# static
For the silent but deadly test every model except static sum performed similarly. Static sum was the least responsive and sensitive of the methods we tried with the lowest max and mean change scores this means that it was the slowest to react and moved the least from day to day. Stability wise it was the highest score since it stayed very consistant. interpretability wise it communicates the sum of previous risk on the line as a risk philosopy closest to a once a criminal always a criminal approach. 
# decayed
The decayed static sum was much more responsive with a max change double the two other summation methods,pretty middle of the pack on sensitivity. It suffers a bit on stability being second lowest, as for interpretability the predicted risk scales down after the incedent taking in only recent history for its risk estimate. 
# rolling window
not very responsive or sensitive with second lowest scores in both. Higer on stability, interpreted in a weird way in that the spike is experinced in reverse going from high to low risk a few days later
# kalman filter
most responsive and sensitive of all the methods, this naturally lead to the lowest stability score. Interpretability wise it leads to a quick spike that recedes just as quickly.
# EWMA
middle of the pack every statistic measured seems to be a happy in-between but doesn't do anything really well. in the graph its longer tail can be seen, showing it holds onto risk better than any other model (but static). 

# Winner 
Its a close battle between EWMA and decayed sum, becasue they are both responsive and sensitive enough to detect the spike. For me it comes down to how they manage there risk score over time, for this reason I think that EWMA beats out the competition because of the way it holds onto risk more gracefully. The aggregated risk score reflects this with a higher AUC than the decayed sum, which in this case I think is appropriate.