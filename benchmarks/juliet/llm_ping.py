import os, sys, time
sys.path.insert(0, '/mnt/d/计算机资料/毕设')
from src.orchestrator.llm_client import LLMClient, LLMConfig

cfg = LLMConfig(provider='openai',
                api_base=os.environ.get('MIMO_API_BASE', 'https://token-plan-ams.xiaomimimo.com/v1'),
                api_key=os.environ['MIMO_API_KEY'],
                model=os.environ.get('MIMO_MODEL', 'mimo-v2.5-pro'))
c = LLMClient(cfg)
t0 = time.time()
r = c.analyze_taint_path_cot(
    {'source': 'fgets', 'sink': 'system', 'vulnerability_type': 'command_injection',
     'source_caller': 'bad', 'sink_caller': 'bad'},
    symbolic_evidence='### Type Information\n- data: char* (conf=0.90)\n### Angr: data flows fgets(stdin) -> system(data)')
print(f"耗时 {time.time()-t0:.1f}s")
print("is_real_taint:", r.get('is_real_taint'), "| confidence:", r.get('confidence'))
print("reasoning(前120字):", str(r.get('reasoning', ''))[:120])
