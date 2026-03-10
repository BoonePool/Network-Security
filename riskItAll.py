import pandas as pd
import numpy as np
import matplotlib.pyplot as plt


def getmetrics(file_path):
    
    df = pd.read_csv(file_path, parse_dates=["date"]) # read in data
    df["cvss"] = df["cvss"].astype(float)

    cvss_sum = []
    static_cum_sum = []
    decayed_cum_sum = []
    rolling_window = []
    kalman_filter = []

    sigma_evol = .1   # set parameters for methods 
    sigma_obs= .05
    uncertainty = 1.0
    EWMA = []
    alpha = 0.25
    decay = .5
    window= 14
    days=0

    for date in pd.date_range(start="2025-08-01", end=df["date"].max()):
        if date in df["date"].values:
            current_cvss_sum = df[df["date"] == date]["cvss"].sum() # sum cvss for current date
        else:
            current_cvss_sum = 0 # pad for days with no data
        cvss_sum.append(current_cvss_sum)  

        if days == 0:
            kalman_filter.append(current_cvss_sum) # initialize methods with first value
            static_cum_sum.append(current_cvss_sum)
            decayed_cum_sum.append(current_cvss_sum)
            rolling_window.append(current_cvss_sum)
            EWMA.append(current_cvss_sum)
        else:
            uncertainty = uncertainty + sigma_evol**2 # kalman uncertainty and gain update
            kalman_gain = uncertainty / (uncertainty + sigma_obs**2)

            static_cum_sum.append(static_cum_sum[-1] + current_cvss_sum) # static cumulative sum

            decayed_cum_sum.append(decayed_cum_sum[-1] * np.exp(-decay) + current_cvss_sum) # decayed cumulative sum

            if days < window: # window warm up
                rolling_window.append(rolling_window[-1] + current_cvss_sum) 
            else: # window full
                rolling_window.append(rolling_window[-1] + current_cvss_sum - cvss_sum[days - window])

            EWMA.append(alpha * current_cvss_sum + (1 - alpha) * EWMA[-1]) # EWMA update

            kalman_filter.append(kalman_filter[-1] + kalman_gain * (current_cvss_sum - kalman_filter[-1]))
            uncertainty = (1 - kalman_gain) * uncertainty
        days += 1
    return static_cum_sum, decayed_cum_sum, rolling_window, kalman_filter, EWMA, cvss_sum





def normalize(series): # normalize values for comparable plotting and metrics
    s = np.array(series, dtype=float)
    if s.min == s.max():
        return np.zeros_like(s)
    return (s - s.min()) / (s.max() - s.min())

def plot_experiment(experiment_name, filename):

    plt.figure(figsize=(10, 5))

    static_cum_sum, decayed_cum_sum, rolling_window, kalman_filter, EWMA, cvss_sum = getmetrics(filename)

    days = np.arange(len(static_cum_sum)) # create x-axis for days since first date
    normalized = normalize(static_cum_sum)
    style = {"color": "blue",   "linestyle": "-"} # set consitiant syle for each method
    plt.plot(days, normalized, label="Static Cumulative Sum", **style)
    normalized = normalize(decayed_cum_sum)
    style = {"color": "red",    "linestyle": "--"}
    plt.plot(days, normalized, label="Decayed Cumulative Sum", **style)
    normalized = normalize(rolling_window)
    style = {"color": "green",  "linestyle": "-."}
    plt.plot(days, normalized, label="Rolling Window", **style)
    normalized = normalize(kalman_filter)
    style = {"color": "orange", "linestyle": ":"}
    plt.plot(days, normalized, label="Kalman Filter", **style)
    normalized = normalize(EWMA)
    style = {"color": "purple", "linestyle": "-"}
    plt.plot(days, normalized, label="EWMA", **style)


    plt.title(f"Risk Assessment — {experiment_name}")
    plt.xlabel("Days since first date")
    plt.ylabel("Normalized Risk")
    plt.legend()
    plt.tight_layout()
    plt.savefig(f"{experiment_name}.png", dpi=150)




plot_experiment("noise/noisy", "data/csc790_noisy_dataset.csv")
plot_experiment("spikez/spikey", "data/csc790_spikey_dataset.csv")
plot_experiment("twoSpikes/two_spikes", "data/csc790_two_spikez_dataset.csv")
def get_stats(filename, location):
    static_cum_sum, decayed_cum_sum, rolling_window, kalman_filter, EWMA, cvss_sum = getmetrics(filename)
    decimal_places = 4

    static_cum_sum = normalize(static_cum_sum) # normalize for comparable metrics
    decayed_cum_sum = normalize(decayed_cum_sum)
    rolling_window = normalize(rolling_window)
    kalman_filter = normalize(kalman_filter)
    EWMA = normalize(EWMA)

    static_change = []
    decayed_change = []
    rolling_change = [] 
    kalman_change = []
    EWMA_change = []
    for i in range(2, len(cvss_sum)): # gather change from day to day for each method, starting at 2 to avoid warm up period for rolling window
        static_change.append((abs(static_cum_sum[i] - static_cum_sum[i-1])))
        decayed_change.append(abs(decayed_cum_sum[i] - decayed_cum_sum[i-1]))
        rolling_change.append(abs(rolling_window[i] - rolling_window[i-1]))
        kalman_change.append(abs(kalman_filter[i] - kalman_filter[i-1]))
        EWMA_change.append(abs(EWMA[i] - EWMA[i-1]))

    max_static_change = np.round(max(static_change), decimal_places)
    max_decayed_change = np.round(max(decayed_change), decimal_places)
    max_rolling_change = np.round(max(rolling_change), decimal_places)
    max_kalman_change = np.round(max(kalman_change), decimal_places)
    max_EWMA_change = np.round(max(EWMA_change), decimal_places)

    mean_static_change = np.round(np.mean(static_change), decimal_places)
    mean_decayed_change = np.round(np.mean(decayed_change), decimal_places)
    mean_rolling_change = np.round(np.mean(rolling_change), decimal_places)
    mean_kalman_change = np.round(np.mean(kalman_change), decimal_places)
    mean_EWMA_change = np.round(np.mean(EWMA_change), decimal_places)

    #Autocorrelation lag
    static_autocorr = np.round(pd.Series(static_cum_sum).autocorr(lag=1), decimal_places)
    decayed_autocorr = np.round(pd.Series(decayed_cum_sum).autocorr(lag=1), decimal_places)
    rolling_autocorr = np.round(pd.Series(rolling_window).autocorr(lag=1), decimal_places)
    kalman_autocorr = np.round(pd.Series(kalman_filter).autocorr(lag=1), decimal_places)
    EWMA_autocorr = np.round(pd.Series(EWMA).autocorr(lag=1), decimal_places)

    #area under curve
    static_auc = np.round(np.trapezoid(static_cum_sum), decimal_places)
    decayed_auc = np.round(np.trapezoid(decayed_cum_sum), decimal_places)
    rolling_auc = np.round(np.trapezoid(rolling_window), decimal_places)
    kalman_auc = np.round(np.trapezoid(kalman_filter), decimal_places)
    EWMA_auc = np.round(np.trapezoid(EWMA), decimal_places)
    
    
    data = {'type': ["static", "decayed", "rolling", "kalman", "EWMA"], 
            'max change': [max_static_change, max_decayed_change, max_rolling_change, max_kalman_change, max_EWMA_change],
            'mean change': [mean_static_change, mean_decayed_change, mean_rolling_change, mean_kalman_change, mean_EWMA_change],
            'autocorrelation': [static_autocorr, decayed_autocorr, rolling_autocorr, kalman_autocorr, EWMA_autocorr],
            'AUC': [static_auc, decayed_auc, rolling_auc, kalman_auc, EWMA_auc]}
    df = pd.DataFrame(data)
    df.to_csv(location, index=False)
get_stats("data/csc790_noisy_dataset.csv", "noise/noise_stats.csv")
get_stats("data/csc790_spikey_dataset.csv", "spikez/spikez_stats.csv")
get_stats("data/csc790_two_spikez_dataset.csv", "twoSpikes/twoSpikes_stats.csv")