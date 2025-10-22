from typing import Dict, List, Optional
from dataclasses import dataclass, field
from datetime import datetime
from langchain_core.callbacks import UsageMetadataCallbackHandler
import os
import threading
import time

@dataclass
class TimelineEntry:
    """Represents an attack timeline entry"""
    event_time: datetime
    event_message: str
    
    def __lt__(self, other):
        return self.event_time < other.event_time

@dataclass
class ToolCall:
    """Represents a tool call invocation"""
    timestamp: datetime
    tool_name: str
    tool_param: str

class DisplayManager:
    """Manages the display of investigation status, attack timeline, and tool usage"""
    
    def __init__(self, refresh_rate: float = 0.5):
        self.refresh_rate = refresh_rate
        self.running = False
        self.display_thread = None
        self.terminal_width = self._get_terminal_width()
        
        # Investigation status
        self.investigation_messages: List[TimelineEntry] = []
        self.investigation_status = "pending"  # pending, inprogress, complete
        
        # Attack timeline
        self.timeline_entries: List[TimelineEntry] = []
        
        # Tool usage
        self.tool_calls: List[ToolCall] = []
        
        self.usage_callback = None
        self.model_name = "Unknown"
        self.input_tokens = 0
        self.output_tokens = 0
        self.total_tokens = 0
    
    def _get_terminal_width(self) -> int:
        """Get terminal width, default to 80 if can't determine"""
        try:
            return os.get_terminal_size().columns
        except:
            return 80
    
    def start_display(self):
        """Start the real-time display thread"""
        if not self.running:
            self.running = True
            self.display_thread = threading.Thread(target=self._display_loop, daemon=True)
            self.display_thread.start()
    
    def stop_display(self):
        """Stop the real-time display"""
        self.running = False
        if self.display_thread:
            self.display_thread.join(timeout=1)
    
    def update_investigation_message(self, message: str, status: str = "inprogress"):
        """Sets the current focus of the investigation, what the agent is looking into"""
        self.investigation_messages.append(TimelineEntry(datetime.now(), message))
        self.investigation_status = status
        self.update_token_use()
    
    def add_timeline_entry(self, event_time: datetime, event_message: str):
        """Adds a recovered attack event to the timeline, sorted by time"""
        entry = TimelineEntry(event_time, event_message)
        self.timeline_entries.append(entry)
        self.update_token_use()
        # Sort by event time (not recovery time)
        self.timeline_entries.sort()
    
    def delete_timeline_entry(self, event_time: datetime, event_message: str):
        """Deletes a timeline entry based on time and message"""
        self.timeline_entries = [
            entry for entry in self.timeline_entries 
            if not (entry.event_time == event_time and entry.event_message == event_message)
        ]
        self.update_token_use()
    
    def add_tool_call(self, tool_name: str, tool_param: str):
        """Adds a tool call invocation to the list"""
        tool_call = ToolCall(
            timestamp=datetime.now(),
            tool_name=tool_name,
            tool_param=tool_param
        )
        self.update_token_use()
        self.tool_calls.append(tool_call)
    
    def update_token_use(self):
        if self.usage_callback is not None:
            self.model_name = next(iter(self.usage_callback.usage_metadata))
            self.input_tokens = self.usage_callback.usage_metadata[self.model_name]['input_tokens']
            self.output_tokens = self.usage_callback.usage_metadata[self.model_name]['output_tokens']
            self.total_tokens = self.usage_callback.usage_metadata[self.model_name]['total_tokens']
        
    def add_usage_object(self, usage_object: UsageMetadataCallbackHandler):
        """Adds a usage object to the list"""
        self.usage_callback = usage_object
    
    def _display_loop(self):
        """Main display loop that updates the terminal"""
        while self.running:
            self._clear_screen()
            self._render_display()
            time.sleep(self.refresh_rate)
    
    def _clear_screen(self):
        """Clear the terminal screen"""
        os.system('clear' if os.name == 'posix' else 'cls')
    
    def _render_display(self):
        """Render the complete display"""
        self._render_header()
        self._render_investigation_status()
        self._render_attack_timeline()
        self._render_tool_usage()
        self._render_token_usage()
        self._render_footer()
    
    def _render_header(self):
        """Render the header section"""
        header = "🔍 CLOUSEAU INVESTIGATION DISPLAY"
        print("=" * self.terminal_width)
        print(f"{header:^{self.terminal_width}}")
        print(f"Last Updated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print("=" * self.terminal_width)
        print()
    
    def _render_investigation_status(self):
        """Render the investigation status section"""
        print("🔍 INVESTIGATION STATUS")
        print("-" * 40)
        
        status_icon = {
            'pending': '⏳',
            'inprogress': '🔄',
            'complete': '✅'
        }.get(self.investigation_status, '❓')
        
        print(f"Status: {status_icon} {self.investigation_status.upper()}")
        if not self.investigation_messages:
            print("Waiting for investigation to start...")
        else:
            for message in self.investigation_messages[-10:]:
                print(f"{message.event_time.strftime('%Y-%m-%d %H:%M:%S')}: {message.event_message}")
        print()
    
    def _render_attack_timeline(self):
        """Render the attack timeline section"""
        print("⏰ ATTACK TIMELINE")
        print("-" * 40)
        
        if not self.timeline_entries:
            print("No attack events recovered yet...")
        else:
            for entry in self.timeline_entries[-10:]:  # Show last 10 events
                time_str = entry.event_time.strftime('%Y-%m-%d %H:%M:%S')
                print(f"{time_str}: {entry.event_message[:self.terminal_width - 40]}")
        
        print()
    
    def _render_tool_usage(self):
        """Render the tool usage section"""
        print("🛠️  TOOL USAGE")
        print("-" * 80)
        
        if not self.tool_calls:
            print("No tool calls recorded yet...")
        else:
            for tool_call in self.tool_calls[-10:]:  # Show last 10 tool calls
                time_str = tool_call.timestamp.strftime('%H:%M:%S')
                tool_param = tool_call.tool_param.replace('\n', ' ')[:self.terminal_width - 40]
                print(f"{time_str}: {tool_call.tool_name}: {tool_param}")
        
        print()
    
    def _render_token_usage(self):
        """Render the token usage section"""
        print(f"🔢 TOKEN USAGE | Model: {self.model_name}")
        print("-" * 80)
        print(f"Input tokens: {self.input_tokens}, Output tokens: {self.output_tokens}, Total tokens: {self.total_tokens}")
        print()
    
    def _render_footer(self):
        """Render the footer section"""
        print("-" * self.terminal_width)
        print("Press Ctrl+C to stop | Auto-refresh every 0.5s")
        print("=" * self.terminal_width)

# Convenience functions for easy integration
def create_display_manager(refresh_rate: float = 0.5) -> DisplayManager:
    """Create and start a display manager"""
    manager = DisplayManager(refresh_rate)
    manager.start_display()
    return manager

def quick_investigation_update(manager: DisplayManager, message: str, status: str = "inprogress"):
    """Quick investigation update helper"""
    manager.update_investigation_message(message, status)

if __name__ == "__main__":
    # Demo usage
    manager = create_display_manager()
    
    # Simulate investigation progress
    time.sleep(1)
    manager.update_investigation_message("Analyzing network traffic patterns for suspicious connections", "inprogress")
    
    time.sleep(1)
    manager.add_timeline_entry(
        datetime(2024, 1, 15, 14, 30, 0),
        "Initial network scan detected unusual outbound connections"
    )
    
    time.sleep(1)
    manager.add_tool_call("nmap", "-sS -p 80,443,22 192.168.1.0/24")
    
    time.sleep(1)
    manager.add_timeline_entry(
        datetime(2024, 1, 15, 14, 35, 0),
        "Port scan revealed open SSH service on non-standard port"
    )
    
    time.sleep(1)
    manager.add_tool_call("ssh_audit", "192.168.1.100:2222")
    
    time.sleep(1)
    manager.update_investigation_message("Investigating SSH service configuration and potential vulnerabilities", "inprogress")
    
    time.sleep(1)
    manager.add_timeline_entry(
        datetime(2024, 1, 15, 14, 40, 0),
        "SSH service running with weak cipher configurations"
    )
    
    time.sleep(1)
    manager.add_tool_call("hydra", "-l admin -P wordlist.txt ssh://192.168.1.100:2222")
    
    time.sleep(1)
    manager.update_investigation_message("Attack timeline reconstruction complete, preparing final report", "complete")
    
    time.sleep(10)
