import json
import os
from pathlib import Path
from typing import Dict, List, Optional, Any
from dataclasses import dataclass


@dataclass
class ExampleQuery:
    """Represents an example query with question, query, and comment."""
    question: str
    query: str
    comment: str

    # str representation of the example query
    def __str__(self):
        s = f"\nQuestion: {self.question}"
        s += f"\nQuery: {self.query}"
        s += f"\nComment: {self.comment}"
        return s

@dataclass
class TableHint:
    """Represents a table hint with description and example queries."""
    table_name: str
    description: str
    examples: List[ExampleQuery]

    # str representation of the table hint
    def __str__(self):
        s = f"\nTable Name: {self.table_name}"
        s += f"\nDescription: {self.description}"
        s += f"\nExamples: \n{('\n\n'.join([str(example) for example in self.examples]))}"
        return s


@dataclass
class Context:
    """Represents the complete context with environment description, data hint, and table hints."""
    env_desc: str
    data_hint: str
    table_hints: Dict[str, TableHint]


class ContextManager:
    """
    Manages context information for different scenarios and tables.
    
    Reads from scenarios_context.json and provides a structured, object-oriented
    interface to access context information.
    """
    
    def __init__(self, context_file_path: str = None):
        """
        Initialize the context manager.
        
        Args:
            context_file_path (str): Path to the scenarios_context.json file.
                                   If None, will look for it in the scenarios directory.
        """
        if context_file_path is None:
            # Default to scenarios/scenarios_context.json relative to current working directory
            current_dir = Path.cwd()
            context_file_path = current_dir / "scenarios" / "scenarios_context.json"
        
        self.context_file_path = Path(context_file_path)
        self.context: Optional[Context] = None
        self._load_context()
    
    def _load_context(self):
        """Load the context data from the JSON file and create structured objects."""
        try:
            if not self.context_file_path.exists():
                print(f"Warning: Context file not found at {self.context_file_path}")
                self.context = None
                return
            
            with open(self.context_file_path, 'r', encoding='utf-8') as f:
                raw_data = json.load(f)
            
            # Parse the raw JSON into structured objects
            self.context = self._parse_context_data(raw_data)
            
        except Exception as e:
            print(f"Error loading context file: {e}")
            self.context = None
    
    def _parse_context_data(self, raw_data: Dict[str, Any]) -> Context:
        """
        Parse raw JSON data into structured Context objects.
        
        Args:
            raw_data: Raw JSON data from the context file
            
        Returns:
            Context object with structured data
        """
        # Extract environment description and data hint
        env_desc = str(raw_data.get('environment_description', ''))
        data_hint = str(raw_data.get('data_hint', ''))
        
        # Parse table hints
        table_hints = {}
        sql_schemas = raw_data.get('sql_schemas', {})
        
        for table_name, table_data in sql_schemas.items():
            # Parse table description
            description = table_data.get('description', '')
            
            # Parse example queries
            examples = []
            raw_examples = table_data.get('example_queries', [])
            
            for example_data in raw_examples:
                example = ExampleQuery(
                    question=example_data.get('question', ''),
                    query=example_data.get('query', ''),
                    comment=example_data.get('comment', '')
                )
                examples.append(example)
            
            # Create TableHint object
            table_hint = TableHint(table_name=table_name, description=description, examples=examples)
            table_hints[table_name] = table_hint
        
        # Create and return Context object
        return Context(
            env_desc=env_desc,
            data_hint=data_hint,
            table_hints=table_hints
        )
    
    def get_context(self) -> Optional[Context]:
        """
        Get the complete context object.
        
        Returns:
            Context object if loaded successfully, None otherwise
        """
        return self.context
    
    def get_environment_description(self) -> str:
        """Get the overall environment description for the scenario."""
        if self.context:
            return self.context.env_desc
        return ""
    
    def get_data_hint(self) -> str:
        """Get the general hint about SQL schemas and data correlation."""
        if self.context:
            return self.context.data_hint
        return ""
    
    def get_available_tables(self) -> List[str]:
        """Get a list of all available tables in the context."""
        if self.context:
            return list(self.context.table_hints.keys())
        return []
    
    def get_table_hint(self, table_name: str) -> str:
        """Get a hint for the table."""
        if self.context:
            return str(self.context.table_hints[table_name])
        return ""
    
    def get_table_summary(self, table_name: str) -> str:
        """Get a summary of the table."""
        if self.context:
            s = self.context.table_hints[table_name].description
            s += f" Examples: {(' '.join([example.question for example in self.context.table_hints[table_name].examples]))}"
            return s
        return ""

    def get_context_summary(self) -> str:
        """Get a summary of the context."""
        if not self.context:
            return "No context information available."
        
        summary_parts = []
        
        # Environment description
        if self.context.env_desc:
            summary_parts.append(f"Here is what we know about the environment:\n{self.context.env_desc}")
        
        # Data hint
        if self.context.data_hint:
            summary_parts.append(f"Collected data:\n{self.context.data_hint}")

        return "\n".join(summary_parts)
       
    def reload_context(self):
        """Reload the context data from the JSON file."""
        self._load_context()
    
    def is_table_available(self, table_name: str) -> bool:
        """Check if context information is available for a specific table."""
        if self.context:
            return table_name in self.context.table_hints
        return False
    
    def get_context_file_path(self) -> str:
        """Get the path to the context file being used."""
        return str(self.context_file_path)
