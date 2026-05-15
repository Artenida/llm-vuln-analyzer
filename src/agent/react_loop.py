from src.agent.state import AgentState
from src.agent.tools import ToolSet
from src.llm.client import LLMClient
from src.models import CodeSample


class ReActAgent:
    def __init__(self, llm: LLMClient, tools: ToolSet):
        self.llm = llm
        self.tools = tools

    def run(self, sample: CodeSample, graph: dict):
        state = AgentState(current_function=sample.function_name)

        observation = self.tools.trace_one_hop(sample.function_name)

        state.memory["context"] = observation

        prompt = self._build_prompt(sample, observation)

        report = self.llm.analyze(sample, context_prompt=prompt)

        state.reasoning_trace.append("analysis_complete")

        return report

    def _build_prompt(self, sample: CodeSample, obs: dict) -> str:
        return f"""
You are a security analysis agent.

Function:
{sample.function_name}

Code:
{sample.code}

Call Graph Context:
{obs}

Return structured vulnerability report.
"""