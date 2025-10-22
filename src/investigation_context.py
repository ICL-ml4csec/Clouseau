from langchain_core.language_models import BaseChatModel
from typing import List, Dict, Any
from src.context_manager import ContextManager
from src.display_manager import DisplayManager
from datetime import datetime

class TimelineEntry:
    """Represents a single entry in the attack timeline."""
    def __init__(self, timestamp: str, event_type: str, description: str, evidence: str = "", confidence: str = "medium"):
        # parse the timestamp into a datetime object
        # so we can sort the timeline
        self.timestamp = datetime.strptime(timestamp, "%Y-%m-%d %H:%M:%S")
        self.event_type = event_type
        self.description = description
        self.evidence = evidence
        self.confidence = confidence
        self.id = f"{timestamp}_{event_type}_{hash(description) % 10000}"
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "timestamp": self.timestamp,
            "event_type": self.event_type,
            "description": self.description,
            "evidence": self.evidence,
            "confidence": self.confidence
        }
    
    def __str__(self) -> str:
        return f"[{self.timestamp}] {self.event_type}: {self.description} (Evidence: {self.evidence}, Confidence: {self.confidence})"

class InvestigationContext(dict):
    def __init__(self, llm: BaseChatModel, context_manager: ContextManager, display: DisplayManager | None, db_name: str, attack_lead: str, max_investigations: int, max_questions: int, max_queries: int):
        self.llm = llm
        self.context_manager = context_manager
        self.display = display
        self.db_name = db_name
        self.attack_lead = attack_lead
        self.max_investigations = max_investigations
        self.max_questions = max_questions
        self.max_queries = max_queries
        self.invocation_max_size = 4096
        self.query_return_max_size = 20480
        self.current_iteration = 0
        self.timeline: List[TimelineEntry] = []

        #if self.display is not None:
        #     self.display.update_investigation_message(attack_lead, 'pending')
        dict.__init__(self, {'db_name': self.db_name})

    def increment_iteration(self):
        self.current_iteration += 1

    def get_current_iteration(self) -> int:
        return self.current_iteration

    def set_investigation(self, investigation_lead: str):
        if self.display is not None:
            self.display.update_investigation_message(investigation_lead, 'inprogress')

    def add_tool_call(self, tool_name: str, tool_param: str):
        if self.display is not None:
            self.display.add_tool_call(tool_name, tool_param)

    def add_timeline_entry(self, timestamp: str, event_type: str, description: str, evidence: str = "", confidence: str = "medium") -> str:
        try:
            # parse the timestamp into a datetime object
            # so we can sort the timeline
            entry = TimelineEntry(timestamp, event_type, description, evidence, confidence)
            print(f"Adding timeline entry: {entry.id}")
            self.timeline.append(entry)
            self.timeline.sort(key=lambda x: x.timestamp)
            if self.display is not None:
                self.display.add_timeline_entry(entry.timestamp, f'{entry.event_type}: {entry.description}')
            return f"Added timeline entry: {entry.id}"
        except Exception as e:
            return f"Error: {e}"
    
    def delete_timeline_entry(self, entry_id: str) -> str:
        try:
            for i, entry in enumerate(self.timeline):
                if entry.id == entry_id:
                    deleted_entry = self.timeline.pop(i)
                    if self.display is not None:
                        self.display.delete_timeline_entry(deleted_entry.timestamp, f'{deleted_entry.event_type}: {deleted_entry.description}')
                    return f"Deleted timeline entry: {deleted_entry.id}"
        except Exception as e:
            return f"Error: {e}"
        return f"Error: Timeline entry with ID '{entry_id}' not found"
    
    def get_timeline(self) -> List[TimelineEntry] | None:
        if len(self.timeline) == 0:
            return None
        # sort the timeline by timestamp
        self.timeline.sort(key=lambda x: x.timestamp)
        return self.timeline

    def timeline_to_str(self) -> str:
        return "\n".join([entry.__str__() for entry in self.timeline])