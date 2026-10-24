import copy
import importlib.util
from pathlib import Path
import unittest

SCRIPT = Path(__file__).resolve().parents[1]/'analyze_trace.py'
spec = importlib.util.spec_from_file_location('analyze_trace',SCRIPT)
analyzer = importlib.util.module_from_spec(spec)
spec.loader.exec_module(analyzer)

def document():
    def sample(sequence, sim, receive):
        return {'sequence':sequence,'entity':2,'generation':1,'active':True,
                'simulation_time':sim,'receive_time':receive,'tick_interval':1/64,
                'origin':[0,0,0],'velocity':[100,0,0],'reported_latency':.100}
    return {'format':analyzer.FORMAT,'version':1,'metadata':{'cvars':{'cl_interp':0,'cl_interp_ratio':1,'cl_updaterate':64}},
            'samples':[sample(1,50,100),sample(2,50+2/64,100+1/64)],
            'events':[{'sequence':3,'kind':'aim_fire','native':{'id':7,'extrapolated':False},'sample_receive_age':.02},
                      {'sequence':4,'kind':'aim_miss','native':{'id':7,'reason':'spread'},'fire_sequence':3},
                      {'sequence':5,'kind':'aim_miss','native':{'id':8,'reason':'?'},'fire_sequence':999}]}

class TraceTests(unittest.TestCase):
    def test_64_tick_and_100ms_are_reported_without_an_aim_shift(self):
        result = analyzer.summarize(document())
        self.assertEqual(result['tick_rates'],[64])
        self.assertEqual(result['reported_latency_ms']['median'],100)
        self.assertAlmostEqual(result['reported_latency_in_ticks']['median'],6.4)
        self.assertEqual(result['estimated_lerp_from_cvars_ms']['median'],15.625)
        self.assertFalse(result['prediction_improvement_measured'])
        self.assertNotIn('suggested_aim_shift',result)
    def test_false_is_different_from_unreported(self):
        flags = analyzer.summarize(document())['native_flags']
        self.assertEqual(flags['extrapolated'],{'false':1})
        self.assertEqual(flags['interpolated'],{'unreported':1})
    def test_shots_are_correlated_by_fire_sequence(self):
        result = analyzer.summarize(document())
        self.assertEqual(result['matched_outcomes'],{'aim_miss':1})
        self.assertEqual(result['unmatched_outcomes'],1)
        self.assertEqual(result['reported_miss_reasons'],{'spread':1,'?':1})
    def test_simulation_and_receive_clocks_are_kept_separate(self):
        result = analyzer.summarize(document())
        self.assertEqual(result['simulation_advance_ticks']['median'],2)
        self.assertEqual(result['receive_gap_ms']['median'],15.625)
        self.assertEqual(result['advances_over_one_tick'],1)
    def test_reset_does_not_create_a_fake_gap(self):
        doc = document()
        doc['samples'][1]['generation'] = 2
        self.assertEqual(analyzer.summarize(doc)['simulation_advance_ticks']['count'],0)
    def test_regressions_and_changed_duplicates_are_preserved(self):
        doc = document()
        doc['samples'][1]['simulation_time'] = 49
        self.assertEqual(analyzer.summarize(doc)['simulation_time_regressions'],1)
        doc['samples'][1]['simulation_time'] = 50
        self.assertEqual(analyzer.summarize(doc)['changed_duplicate_simulation_times'],1)
    def test_server_lerp_constraints_and_zero_ratio(self):
        self.assertEqual(analyzer.estimated_lerp({'cl_interp':0,'cl_interp_ratio':0,'cl_updaterate':64}),1/64)
        self.assertEqual(analyzer.estimated_lerp({'cl_interp':0,'cl_interp_ratio':1,'cl_updaterate':128,
            'sv_minupdaterate':64,'sv_maxupdaterate':64,'sv_client_min_interp_ratio':2,
            'sv_client_max_interp_ratio':2}),2/64)
        self.assertEqual(analyzer.estimated_lerp({'cl_interp':.05,'cl_interp_ratio':1,'cl_updaterate':64}),.05)
        self.assertIsNone(analyzer.estimated_lerp({'cl_interp':0,'cl_interp_ratio':1,'cl_updaterate':0}))
    def test_malformed_and_nonfinite_samples_are_rejected(self):
        for value in (float('nan'),float('inf'),False):
            doc = document(); doc['samples'][0]['origin'][0] = value
            with self.assertRaises(ValueError): analyzer.summarize(doc)
        doc = document(); doc['samples'][1]['sequence'] = 1
        with self.assertRaises(ValueError): analyzer.summarize(doc)
    def test_empty_lua_tables_are_supported(self):
        doc = document(); doc['samples'] = {}; doc['events'] = {}
        result = analyzer.summarize(doc)
        self.assertEqual(result['active_samples'],0)
        self.assertEqual(result['aim_fire_events'],0)
    def test_lua_integer_values_encoded_as_floats(self):
        doc = document(); doc['version'] = 1.0
        for row in doc['samples']:
            for key in ('sequence', 'entity', 'generation'): row[key] = float(row[key])
        self.assertEqual(analyzer.summarize(doc)['active_samples'],2)
    def test_input_is_not_modified(self):
        doc = document(); before = copy.deepcopy(doc)
        analyzer.summarize(doc)
        self.assertEqual(doc,before)

if __name__=='__main__': unittest.main()
