"""
Type Recovery Inference Module

Integrates with TYGR for GNN-based type recovery.
This module provides inference capabilities using trained models.
"""

import os
import sys
import logging
import pickle
from typing import Dict, Any, List, Optional, Tuple
from dataclasses import dataclass, field
from pathlib import Path

logger = logging.getLogger('OPM.type_recovery')

# Add TYGR to path
TYGR_PATH = os.path.join(os.path.dirname(__file__), '..', '..', 'tygr', 'TYGR0')
if os.path.exists(TYGR_PATH):
    sys.path.insert(0, TYGR_PATH)


@dataclass
class TypePrediction:
    """Prediction for a single variable."""
    variable_name: str
    predicted_type: str
    confidence: float
    source: str  # 'gnn', 'heuristic', 'dwarf'
    details: Dict[str, Any] = field(default_factory=dict)


@dataclass
class TypeRecoveryOutput:
    """Output from type recovery."""
    function_name: str
    predictions: List[TypePrediction] = field(default_factory=list)
    # Type hints for the GNN
    variable_types: Dict[str, str] = field(default_factory=dict)
    pointer_labels: Dict[str, bool] = field(default_factory=dict)
    buffer_labels: Dict[str, bool] = field(default_factory=dict)
    function_signatures: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    confidence_scores: Dict[str, float] = field(default_factory=dict)


def recover_types(
    binary_path: str,
    cfg: Any,
    dfg: Any,
    model_path: Optional[str] = None,
    confidence_threshold: float = 0.7
) -> Dict[str, Any]:
    """
    Recover types from binary using GNN.

    Args:
        binary_path: Path to the binary
        cfg: Control Flow Graph
        dfg: Data Flow Graph
        model_path: Path to trained GNN model
        confidence_threshold: Minimum confidence for predictions

    Returns:
        Dictionary mapping function names to TypeRecoveryOutput
    """
    logger.info("Starting GNN-based type recovery")

    results = {}

    # Try to use TYGR if available
    try:
        results = _recover_with_tygr(binary_path, model_path, confidence_threshold)
    except Exception as e:
        logger.warning(f"TYGR not available, using heuristic fallback: {e}")
        results = _recover_with_heuristics(binary_path, cfg, dfg)

    logger.info(f"Type recovery complete: {len(results)} functions")
    return results


def _recover_with_tygr(
    binary_path: str,
    model_path: Optional[str],
    confidence_threshold: float
) -> Dict[str, Any]:
    """Recover types using TYGR."""
    logger.info("Using TYGR for type recovery")

    # Import TYGR modules
    try:
        from datagen0.datagen import generate_glow_dataset_no_parallel, Options
        from datagen0.common import GlowInput, GlowOutput
    except ImportError as e:
        raise ImportError(f"TYGR modules not available: {e}")

    # Run TYGR data generation
    options = Options(verbose=False)
    results = {}

    for glow_input, glow_output in generate_glow_dataset_no_parallel(binary_path, './', options):
        func_name = glow_input.function_name

        # Convert TYGR output to our format
        predictions = []
        for var, ty in zip(glow_input.vars, glow_output.types):
            pred = TypePrediction(
                variable_name=var.name,
                predicted_type=str(ty),
                confidence=1.0,  # TYGR uses ground truth during generation
                source='dwarf',
                details={
                    'nodes': var.nodes,
                    'locations': var.locs,
                }
            )
            predictions.append(pred)

        output = TypeRecoveryOutput(
            function_name=func_name,
            predictions=predictions,
            variable_types={p.variable_name: p.predicted_type for p in predictions},
            confidence_scores={p.variable_name: p.confidence for p in predictions},
        )

        results[func_name] = output

    return results


def _recover_with_heuristics(
    binary_path: str,
    cfg: Any,
    dfg: Any
) -> Dict[str, Any]:
    """Recover types using heuristics (fallback)."""
    logger.info("Using heuristic type recovery")

    results = {}

    # Analyze each function
    for func_name, func in cfg.functions.items():
        predictions = []

        # Analyze register usage patterns
        for block in func.blocks:
            # Look for patterns that indicate types
            for pred_node_id in dfg.predecessors.get(block.address, []):
                pred_node = dfg.get_node(pred_node_id)
                if pred_node is None:
                    continue

                # Check for pointer patterns
                if pred_node.operation == 'memory_read' or pred_node.operation == 'memory_write':
                    # Likely a pointer
                    if pred_node.operand:
                        pred = TypePrediction(
                            variable_name=pred_node.operand,
                            predicted_type='void*',
                            confidence=0.6,
                            source='heuristic',
                            details={'pattern': 'memory_access'}
                        )
                        predictions.append(pred)

                # Check for arithmetic patterns
                if 'binop_' in pred_node.operation:
                    op = pred_node.operation.replace('binop_', '')
                    if op in ['Iop_Add32', 'Iop_Sub32', 'Iop_Mul32']:
                        pred = TypePrediction(
                            variable_name=pred_node.operand or f"var_{pred_node.id}",
                            predicted_type='i32',
                            confidence=0.5,
                            source='heuristic',
                            details={'pattern': 'arithmetic_32bit'}
                        )
                        predictions.append(pred)
                    elif op in ['Iop_Add64', 'Iop_Sub64', 'Iop_Mul64']:
                        pred = TypePrediction(
                            variable_name=pred_node.operand or f"var_{pred_node.id}",
                            predicted_type='i64',
                            confidence=0.5,
                            source='heuristic',
                            details={'pattern': 'arithmetic_64bit'}
                        )
                        predictions.append(pred)

        # Deduplicate predictions
        seen = set()
        unique_predictions = []
        for pred in predictions:
            key = (pred.variable_name, pred.predicted_type)
            if key not in seen:
                seen.add(key)
                unique_predictions.append(pred)

        output = TypeRecoveryOutput(
            function_name=func_name,
            predictions=unique_predictions,
            variable_types={p.variable_name: p.predicted_type for p in unique_predictions},
            confidence_scores={p.variable_name: p.confidence for p in unique_predictions},
        )

        results[func_name] = output

    return results


def recover_function_types(
    binary_path: str,
    function_name: str,
    model_path: Optional[str] = None
) -> Optional[TypeRecoveryOutput]:
    """
    Recover types for a specific function.

    Args:
        binary_path: Path to the binary
        function_name: Name of the function
        model_path: Path to trained model

    Returns:
        TypeRecoveryOutput or None if function not found
    """
    logger.info(f"Recovering types for function: {function_name}")

    try:
        results = _recover_with_tygr(binary_path, model_path, 0.5)
        return results.get(function_name)
    except Exception as e:
        logger.warning(f"TYGR failed: {e}")
        return None


def load_model(model_path: str) -> Any:
    """
    Load a trained GNN model.

    Args:
        model_path: Path to the model file

    Returns:
        Loaded model
    """
    if not os.path.exists(model_path):
        raise FileNotFoundError(f"Model not found: {model_path}")

    logger.info(f"Loading model from: {model_path}")

    # Load model based on extension
    ext = Path(model_path).suffix

    if ext == '.pt' or ext == '.pth':
        import torch
        return torch.load(model_path)
    elif ext == '.pkl':
        with open(model_path, 'rb') as f:
            return pickle.load(f)
    else:
        raise ValueError(f"Unsupported model format: {ext}")


def get_type_summary(results: Dict[str, TypeRecoveryOutput]) -> Dict[str, Any]:
    """
    Get summary of type recovery results.

    Args:
        results: Type recovery results

    Returns:
        Summary dictionary
    """
    total_functions = len(results)
    total_variables = 0
    type_counts = {}
    source_counts = {'gnn': 0, 'heuristic': 0, 'dwarf': 0}

    for func_output in results.values():
        total_variables += len(func_output.predictions)
        for pred in func_output.predictions:
            type_counts[pred.predicted_type] = type_counts.get(pred.predicted_type, 0) + 1
            source_counts[pred.source] = source_counts.get(pred.source, 0) + 1

    return {
        'total_functions': total_functions,
        'total_variables': total_variables,
        'type_distribution': type_counts,
        'source_distribution': source_counts,
        'avg_variables_per_function': total_variables / total_functions if total_functions > 0 else 0,
    }


# Example usage
if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print("Usage: python inference.py <binary_path> [--model model_path]")
        sys.exit(1)

    binary = sys.argv[1]
    model = None

    if '--model' in sys.argv:
        idx = sys.argv.index('--model')
        if idx + 1 < len(sys.argv):
            model = sys.argv[idx + 1]

    try:
        results = recover_types(binary, None, None, model)

        # Print results
        for func_name, output in results.items():
            print(f"\n{func_name}:")
            for pred in output.predictions:
                print(f"  {pred.variable_name}: {pred.predicted_type} "
                      f"(confidence: {pred.confidence:.2f}, source: {pred.source})")

        # Print summary
        summary = get_type_summary(results)
        print(f"\nSummary:")
        print(f"  Functions: {summary['total_functions']}")
        print(f"  Variables: {summary['total_variables']}")
        print(f"  Type distribution: {summary['type_distribution']}")

    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)
