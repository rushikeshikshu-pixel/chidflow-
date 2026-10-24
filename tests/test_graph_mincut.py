import unittest
from chidflow.graph import DynamicFlowGraph
from chidflow.models import SecurityClassification


class TestDynamicFlowGraph(unittest.TestCase):
    def setUp(self):
        self.graph = DynamicFlowGraph()

    def test_checkpoint_and_rollback(self):
        self.graph.add_node("nodeA", SecurityClassification.AGENT_CONTEXT)
        self.graph.add_node("nodeB", SecurityClassification.CRITICAL_SINK)

        self.graph.checkpoint()
        self.graph.add_edge("nodeA", "nodeB", capacity=1.0)
        self.assertEqual(len(self.graph.edges), 1)

        self.graph.rollback()
        self.assertEqual(len(self.graph.edges), 0)

    def test_min_cut_disconnects_source_and_sink(self):
        # Topology: Source -> Middle1 -> Sink
        #                   \-> Middle2 -/
        self.graph.add_node("src", SecurityClassification.UNTRUSTED_SOURCE)
        self.graph.add_node("m1", SecurityClassification.AGENT_CONTEXT)
        self.graph.add_node("m2", SecurityClassification.AGENT_CONTEXT)
        self.graph.add_node("sink", SecurityClassification.CRITICAL_SINK)

        self.graph.add_edge("src", "m1", capacity=1.0)
        self.graph.add_edge("src", "m2", capacity=1.0)
        self.graph.add_edge("m1", "sink", capacity=1.0)
        self.graph.add_edge("m2", "sink", capacity=1.0)

        flow, choke_points = self.graph.compute_min_cut(["src"], ["sink"])
        self.assertEqual(flow, 2.0)
        self.assertTrue(len(choke_points) > 0)

    def test_isolated_components_zero_flow(self):
        self.graph.add_node("src", SecurityClassification.UNTRUSTED_SOURCE)
        self.graph.add_node("sink", SecurityClassification.CRITICAL_SINK)

        flow, choke_points = self.graph.compute_min_cut(["src"], ["sink"])
        self.assertEqual(flow, 0.0)
        self.assertEqual(choke_points, [])


if __name__ == "__main__":
    unittest.main()
