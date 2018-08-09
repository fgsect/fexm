import unittest
import os

parentdir = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
os.sys.path.insert(0, parentdir)
from configfinder.coverage_evaluator import CoverageEvaluator


class TestCoverageEvaluator(unittest.TestCase):
    def testDeviationScores(self):
        test_input = [["pdf", "jpg"], [100, 200]]
        ce = CoverageEvaluator(type_coverage_list=test_input)
        assert (ce.calculate_deviation_scores() == [["pdf", "jpg"], [0, 1]])
        test_input = [["pdf", "jpg"], [50, 50]]
        ce = CoverageEvaluator(type_coverage_list=test_input)
        assert (ce.calculate_deviation_scores() == [["pdf", "jpg"], [0, 0]])

    def testPlotter(self):
        test_input = [["abc"] * 91, ([100] * 90) + [101]]
        ce = CoverageEvaluator(type_coverage_list=test_input)
        ce.plot(binary_path="test/test", figure_path="test_figures", parameter=None, plot_format="tex")

    def plotCppPlot(self):
        test_input = [
            ['', '', '', '', '', '', '', '', '', '', '', '', '', '', '', '', '', '', '', '', '', '', '', '', '', '', '',
             '',
             '', '', '', '', '', '', '', '', '', '', '', '', '', '', '', 'mod', '', '', '', '', '', '', '', '', '', '',
             '',
             '', '', '', '', '', '', '', '', '', '', '', '', '', '', '', '', '', '', '', '', '', '', '', '', '', '', '',
             '',
             '', '', '', '', '', '', ''],
            [19761.0, 19509.0, 19503.0, 19562.0, 19705.0, 19938.0, 21839.0, 19365.0, 19807.0, 22172.0, 19696.0, 25307.0,
             25381.0, 19722.0, 25688.0, 19544.0, 19209.0, 19598.0, 19636.0, 19449.0, 21852.0, 24868.0, 19566.0, 19337.0,
             19752.0, 19806.0, 25896.0, 19218.0, 19836.0, 19626.0, 19960.0, 24948.0, 19530.0, 19445.0, 26243.0, 19733.0,
             25555.0, 19748.0, 19722.0, 19280.0, 19410.0, 25472.0, 19791.0, 36628.0, 19660.0, 19721.0, 19642.0, 19180.0,
             26105.0, 19492.0, 20260.0, 19803.0, 19453.0, 19508.0, 19850.0, 19469.0, 20170.0, 19621.0, 19603.0, 19801.0,
             19763.0, 25138.0, 19376.0, 19333.0, 19884.0, 27680.0, 35220.0, 19273.0, 19578.0, 19205.0, 25425.0, 19498.0,
             25823.0, 19374.0, 19216.0, 19147.0, 26174.0, 26960.0, 19810.0, 21878.5, 19959.0, 19541.0, 25525.0, 19953.0,
             19501.0, 19431.0, 19465.0, 19715.0, 19697.0, 19568.0]]
        ce = CoverageEvaluator(type_coverage_list=test_input)
        ce.plot(binary_path="test/cpp", figure_path="test_figures", parameter=None, plot_format="tex")

    def testEmptyList(self):
        ce = CoverageEvaluator(type_coverage_list=[[], []])
        with self.assertRaises(ValueError):
            ce.plot(binary_path="test/cpp", figure_path="test_figures", parameter=None, plot_format="tex")


if __name__ == '__main__':
    unittest.main()
