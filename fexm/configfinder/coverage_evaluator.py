import matplotlib
import os
import scipy as sp

matplotlib.use("Agg")
import matplotlib.pyplot as plt


class CoverageEvaluator(object):
    """
    This class can be used to examine the file-type/code coverage distribution in a file.  
    """

    def __init__(self, type_coverage_list: [[str], [int]]):
        """
        :param type_coverage_list: A list containing two lists: 1) The list of file types. 2) The corresponding list of reached code coverage.
        :param max_coverage_possible: The maximum coverage possible. Need to calculate the percent of reached coverage.
        """
        self.type_coverage_list = type_coverage_list

    def calculate_deviation_scores(self) -> [[str], [float]]:
        """
        For each file type, calculate a deviation score: 
        $$ p(x) = \begin{cases}
	            \frac{x-\bar{x}}{\sum_{x > \bar{x}} x-\bar{x}} & if x > \bar{x} \\
	            0 & else
	        \end{cases}$$
	    where $x$ is the coverage corresponding to that filetype.
        :return: A list of two lists: The file types and the corresponding deviation scores.
        """
        deviation_scores = sp.zeros(len(self.type_coverage_list[1]))
        mean = sp.mean(self.type_coverage_list[1])  # Calculate $bar{x}$, the mean over all code coverages
        above_zero_idx = sp.where(self.type_coverage_list[1] >= mean)[0]
        sum_of_above_zero = 0  # sum_{x > \bar{x}} x-\bar{x}
        for idx in above_zero_idx:
            sum_of_above_zero += (self.type_coverage_list[1][idx] - mean)
            deviation_scores[idx] = self.type_coverage_list[1][idx] - mean
        # if sum_of_above_zero>0:
        #    deviation_scores = deviation_scores/sum_of_above_zero # Normalize
        self.deviation_scores = deviation_scores
        deviation_scores_list = list(deviation_scores)
        return [self.type_coverage_list[0], deviation_scores_list]

    def calculate_chebyshev_score(self):
        """
        This function calculates the chebyshev score. That is, we calculate the deviation from the 
        mean divided by the standard deviation and then calculate the probality of this value. The least likely the value is, 
        the higher is the chebyshev score. 
        k^2 = \frac{(x-\bar{x})^2}{\frac{1}{N-1}\sum_{x \in X} {(x - \bar{x})^2}}$$
        :return: 
        """
        chebyshev_scores = sp.zeros(len(self.type_coverage_list[1]))
        mean = sp.mean(self.type_coverage_list[1])  # Calculate $bar{x}$, the mean over all code coverages
        above_zero_idx = sp.where(self.type_coverage_list[1] >= mean)[0]
        # variance = sp.var(self.type_coverage_list[1])
        std = sp.std(self.type_coverage_list[1])
        for idx in above_zero_idx:
            # chebyshev_scores[idx] = (self.type_coverage_list[1][idx] - mean)**2
            chebyshev_scores[idx] = (self.type_coverage_list[1][idx] - mean)
        if std > 0:
            chebyshev_scores = chebyshev_scores / std
        # if variance>0:
        #    chebyshev_scores = chebyshev_scores / variance
        # sum = sp.sum(chebyshev_scores)
        # if sum > 0:
        #    chebyshev_scores /= sum
        self.chebyshev_scores = chebyshev_scores

        return [self.type_coverage_list[0], list(chebyshev_scores)]

    def plot(self, binary_path: str, figure_path: str, parameter: str, plot_format: str = "png"):
        """
        Plot the coverage as a function of the filetypes on x-axis and 
            coverage on the y-axis
            
        :param binary_path: The path to the binary (later used for name generation) 
        :param figure_path: The directory where the figure should be saved
        :param parameter: The parameter that is used to invoke the bianry.
        :param plot_format: Save to which format
        """
        # number_of_tuples = max_coverage_possible
        cov_list = self.type_coverage_list[1]
        file_list = self.type_coverage_list[0]
        if not cov_list or not file_list:
            raise ValueError("Coverage or Filetype list empty!")
        if len(cov_list) != len(file_list):
            raise ValueError("List have different lengths!")
        matplotlib.use("Agg")
        fig = plt.figure(figsize=(len(file_list) * 0.3, 10))
        ax = fig.add_subplot(111)
        # fig, ax = plt.subplots()
        zipped_list = zip(file_list, cov_list)
        zipped_list = sorted(zipped_list, key=lambda x: x[0])
        ordered_file_list = list(zip(*zipped_list))[0]
        ordered_cov_list = list(zip(*zipped_list))[1]
        # ordered_cov_list = list(map(lambda x: ((float(x) / number_of_tuples) * 100), ordered_cov_list))
        # print(number_of_tuples)
        max_index = sp.where(sp.array(ordered_cov_list) == max(ordered_cov_list))
        rects1 = ax.bar(sp.arange(len(cov_list)), ordered_cov_list, 0.35, color='r')

        y_label_list = [''] * len(ordered_file_list)
        for ind in max_index[0]:  # Mark highest bar blue
            rects1[ind].set_color('b')
            y_label_list[ind] = ordered_file_list[ind]

        print(y_label_list)
        print(ordered_cov_list)
        # ax.xticks(cov_list,file_list)
        # ax.set_ylim(0,max(ordered_cov_list))
        # ax.set_ylim(0,100)
        ax.set_xticks(sp.arange(len(ordered_file_list)))
        ax.set_xlabel("Filetypes", fontsize=14, fontweight='bold')
        ax.set_ylabel("Coverage in tuples", fontsize=14, fontweight='bold')
        ax.set_xticklabels(y_label_list, fontsize=12, rotation=90)
        # ax.xaxis.set_tick_params(width=5)
        print(binary_path)
        p = "None"
        if parameter:
            p = parameter
        ax.set_title(str(binary_path))

        if plot_format == "png":
            fig.savefig(figure_path + "/" + str(os.path.basename(binary_path)) + "_" + str(p) + ".png",
                        dpi=fig.dpi)
        else:
            from matplotlib2tikz import save as tikz_save
            tikz_save(figure_path + "/" + str(os.path.basename(binary_path)) + "_" + str(p) + ".tex",
                      figurewidth='\\textwidth', figureheight='\\textheight')
        plt.close(fig)
