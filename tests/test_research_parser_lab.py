import pytest
from secopsai.research_parser_lab import run_lab


def test_disposable_parser_lab_is_reproducible_and_nonexecuting(monkeypatch):
    monkeypatch.setenv('TYPESAFE_API_KEY','synthetic-secret-must-not-leave-parent')
    first=run_lab(seed=42,cases=100)
    second=run_lab(seed=42,cases=100)
    assert first==second and first['status']=='passed'
    assert first['accepted']+first['rejected']==first['cases']
    assert first['failure_count']==0 and first['model_jobs_created']==0
    assert not first['network_performed'] and not first['package_execution_performed']
    assert 'synthetic-secret' not in str(first)


@pytest.mark.parametrize('config',[{'cases':1000000},{'seed':-1},{'seconds':0},{'cases':True}])
def test_lab_rejects_unbounded_or_ambiguous_configuration(config):
    with pytest.raises(ValueError):run_lab(**config)
