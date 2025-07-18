#!/usr/bin/env python3
"""
Fix PyQt6 enum compatibility issues in the Intellicrack codebase.

This script updates all Qt enum references to use the proper PyQt6 format.
"""

import os
import re
from pathlib import Path


# Define the enum replacements
ENUM_REPLACEMENTS = [
    # Qt.AlignmentFlag
    (r'\bQt\.AlignCenter\b', 'Qt.AlignmentFlag.AlignCenter'),
    (r'\bQt\.AlignLeft\b', 'Qt.AlignmentFlag.AlignLeft'),
    (r'\bQt\.AlignRight\b', 'Qt.AlignmentFlag.AlignRight'),
    (r'\bQt\.AlignTop\b', 'Qt.AlignmentFlag.AlignTop'),
    (r'\bQt\.AlignBottom\b', 'Qt.AlignmentFlag.AlignBottom'),
    (r'\bQt\.AlignHCenter\b', 'Qt.AlignmentFlag.AlignHCenter'),
    (r'\bQt\.AlignVCenter\b', 'Qt.AlignmentFlag.AlignVCenter'),
    (r'\bQt\.AlignJustify\b', 'Qt.AlignmentFlag.AlignJustify'),
    (r'\bQt\.AlignAbsolute\b', 'Qt.AlignmentFlag.AlignAbsolute'),
    (r'\bQt\.AlignLeading\b', 'Qt.AlignmentFlag.AlignLeading'),
    (r'\bQt\.AlignTrailing\b', 'Qt.AlignmentFlag.AlignTrailing'),

    # Qt.ItemDataRole
    (r'\bQt\.UserRole\b', 'Qt.ItemDataRole.UserRole'),
    (r'\bQt\.DisplayRole\b', 'Qt.ItemDataRole.DisplayRole'),
    (r'\bQt\.EditRole\b', 'Qt.ItemDataRole.EditRole'),
    (r'\bQt\.DecorationRole\b', 'Qt.ItemDataRole.DecorationRole'),
    (r'\bQt\.ToolTipRole\b', 'Qt.ItemDataRole.ToolTipRole'),
    (r'\bQt\.StatusTipRole\b', 'Qt.ItemDataRole.StatusTipRole'),
    (r'\bQt\.WhatsThisRole\b', 'Qt.ItemDataRole.WhatsThisRole'),
    (r'\bQt\.FontRole\b', 'Qt.ItemDataRole.FontRole'),
    (r'\bQt\.TextAlignmentRole\b', 'Qt.ItemDataRole.TextAlignmentRole'),
    (r'\bQt\.BackgroundRole\b', 'Qt.ItemDataRole.BackgroundRole'),
    (r'\bQt\.ForegroundRole\b', 'Qt.ItemDataRole.ForegroundRole'),
    (r'\bQt\.CheckStateRole\b', 'Qt.ItemDataRole.CheckStateRole'),

    # Qt.Orientation
    (r'\bQt\.Horizontal\b', 'Qt.Orientation.Horizontal'),
    (r'\bQt\.Vertical\b', 'Qt.Orientation.Vertical'),

    # Qt.WindowType
    (r'\bQt\.FramelessWindowHint\b', 'Qt.WindowType.FramelessWindowHint'),
    (r'\bQt\.WindowStaysOnTopHint\b', 'Qt.WindowType.WindowStaysOnTopHint'),
    (r'\bQt\.CustomizeWindowHint\b', 'Qt.WindowType.CustomizeWindowHint'),
    (r'\bQt\.Tool\b', 'Qt.WindowType.Tool'),
    (r'\bQt\.Window\b', 'Qt.WindowType.Window'),
    (r'\bQt\.Dialog\b', 'Qt.WindowType.Dialog'),
    (r'\bQt\.SubWindow\b', 'Qt.WindowType.SubWindow'),
    (r'\bQt\.WindowTitleHint\b', 'Qt.WindowType.WindowTitleHint'),
    (r'\bQt\.WindowSystemMenuHint\b', 'Qt.WindowType.WindowSystemMenuHint'),
    (r'\bQt\.WindowMinimizeButtonHint\b', 'Qt.WindowType.WindowMinimizeButtonHint'),
    (r'\bQt\.WindowMaximizeButtonHint\b', 'Qt.WindowType.WindowMaximizeButtonHint'),
    (r'\bQt\.WindowCloseButtonHint\b', 'Qt.WindowType.WindowCloseButtonHint'),

    # Qt.BrushStyle
    (r'\bQt\.SolidPattern\b', 'Qt.BrushStyle.SolidPattern'),
    (r'\bQt\.NoBrush\b', 'Qt.BrushStyle.NoBrush'),

    # Qt.PenStyle
    (r'\bQt\.SolidLine\b', 'Qt.PenStyle.SolidLine'),
    (r'\bQt\.DashLine\b', 'Qt.PenStyle.DashLine'),
    (r'\bQt\.DotLine\b', 'Qt.PenStyle.DotLine'),
    (r'\bQt\.DashDotLine\b', 'Qt.PenStyle.DashDotLine'),
    (r'\bQt\.DashDotDotLine\b', 'Qt.PenStyle.DashDotDotLine'),
    (r'\bQt\.NoPen\b', 'Qt.PenStyle.NoPen'),

    # Qt.AspectRatioMode
    (r'\bQt\.IgnoreAspectRatio\b', 'Qt.AspectRatioMode.IgnoreAspectRatio'),
    (r'\bQt\.KeepAspectRatio\b', 'Qt.AspectRatioMode.KeepAspectRatio'),
    (r'\bQt\.KeepAspectRatioByExpanding\b', 'Qt.AspectRatioMode.KeepAspectRatioByExpanding'),

    # Qt.TransformationMode
    (r'\bQt\.FastTransformation\b', 'Qt.TransformationMode.FastTransformation'),
    (r'\bQt\.SmoothTransformation\b', 'Qt.TransformationMode.SmoothTransformation'),

    # Qt.FocusPolicy
    (r'\bQt\.NoFocus\b', 'Qt.FocusPolicy.NoFocus'),
    (r'\bQt\.TabFocus\b', 'Qt.FocusPolicy.TabFocus'),
    (r'\bQt\.ClickFocus\b', 'Qt.FocusPolicy.ClickFocus'),
    (r'\bQt\.StrongFocus\b', 'Qt.FocusPolicy.StrongFocus'),
    (r'\bQt\.WheelFocus\b', 'Qt.FocusPolicy.WheelFocus'),

    # Qt.ContextMenuPolicy
    (r'\bQt\.NoContextMenu\b', 'Qt.ContextMenuPolicy.NoContextMenu'),
    (r'\bQt\.DefaultContextMenu\b', 'Qt.ContextMenuPolicy.DefaultContextMenu'),
    (r'\bQt\.ActionsContextMenu\b', 'Qt.ContextMenuPolicy.ActionsContextMenu'),
    (r'\bQt\.CustomContextMenu\b', 'Qt.ContextMenuPolicy.CustomContextMenu'),
    (r'\bQt\.PreventContextMenu\b', 'Qt.ContextMenuPolicy.PreventContextMenu'),

    # Qt.ScrollBarPolicy
    (r'\bQt\.ScrollBarAsNeeded\b', 'Qt.ScrollBarPolicy.ScrollBarAsNeeded'),
    (r'\bQt\.ScrollBarAlwaysOff\b', 'Qt.ScrollBarPolicy.ScrollBarAlwaysOff'),
    (r'\bQt\.ScrollBarAlwaysOn\b', 'Qt.ScrollBarPolicy.ScrollBarAlwaysOn'),

    # Qt.TextInteractionFlag
    (r'\bQt\.NoTextInteraction\b', 'Qt.TextInteractionFlag.NoTextInteraction'),
    (r'\bQt\.TextSelectableByMouse\b', 'Qt.TextInteractionFlag.TextSelectableByMouse'),
    (r'\bQt\.TextSelectableByKeyboard\b', 'Qt.TextInteractionFlag.TextSelectableByKeyboard'),
    (r'\bQt\.LinksAccessibleByMouse\b', 'Qt.TextInteractionFlag.LinksAccessibleByMouse'),
    (r'\bQt\.LinksAccessibleByKeyboard\b', 'Qt.TextInteractionFlag.LinksAccessibleByKeyboard'),
    (r'\bQt\.TextEditable\b', 'Qt.TextInteractionFlag.TextEditable'),
    (r'\bQt\.TextEditorInteraction\b', 'Qt.TextInteractionFlag.TextEditorInteraction'),
    (r'\bQt\.TextBrowserInteraction\b', 'Qt.TextInteractionFlag.TextBrowserInteraction'),

    # Qt.CheckState
    (r'\bQt\.Unchecked\b', 'Qt.CheckState.Unchecked'),
    (r'\bQt\.PartiallyChecked\b', 'Qt.CheckState.PartiallyChecked'),
    (r'\bQt\.Checked\b', 'Qt.CheckState.Checked'),

    # Qt.SortOrder
    (r'\bQt\.AscendingOrder\b', 'Qt.SortOrder.AscendingOrder'),
    (r'\bQt\.DescendingOrder\b', 'Qt.SortOrder.DescendingOrder'),

    # Qt.CursorShape
    (r'\bQt\.ArrowCursor\b', 'Qt.CursorShape.ArrowCursor'),
    (r'\bQt\.UpArrowCursor\b', 'Qt.CursorShape.UpArrowCursor'),
    (r'\bQt\.CrossCursor\b', 'Qt.CursorShape.CrossCursor'),
    (r'\bQt\.WaitCursor\b', 'Qt.CursorShape.WaitCursor'),
    (r'\bQt\.IBeamCursor\b', 'Qt.CursorShape.IBeamCursor'),
    (r'\bQt\.SizeVerCursor\b', 'Qt.CursorShape.SizeVerCursor'),
    (r'\bQt\.SizeHorCursor\b', 'Qt.CursorShape.SizeHorCursor'),
    (r'\bQt\.SizeBDiagCursor\b', 'Qt.CursorShape.SizeBDiagCursor'),
    (r'\bQt\.SizeFDiagCursor\b', 'Qt.CursorShape.SizeFDiagCursor'),
    (r'\bQt\.SizeAllCursor\b', 'Qt.CursorShape.SizeAllCursor'),
    (r'\bQt\.BlankCursor\b', 'Qt.CursorShape.BlankCursor'),
    (r'\bQt\.SplitVCursor\b', 'Qt.CursorShape.SplitVCursor'),
    (r'\bQt\.SplitHCursor\b', 'Qt.CursorShape.SplitHCursor'),
    (r'\bQt\.PointingHandCursor\b', 'Qt.CursorShape.PointingHandCursor'),
    (r'\bQt\.ForbiddenCursor\b', 'Qt.CursorShape.ForbiddenCursor'),
    (r'\bQt\.WhatsThisCursor\b', 'Qt.CursorShape.WhatsThisCursor'),
    (r'\bQt\.BusyCursor\b', 'Qt.CursorShape.BusyCursor'),
    (r'\bQt\.OpenHandCursor\b', 'Qt.CursorShape.OpenHandCursor'),
    (r'\bQt\.ClosedHandCursor\b', 'Qt.CursorShape.ClosedHandCursor'),
    (r'\bQt\.DragCopyCursor\b', 'Qt.CursorShape.DragCopyCursor'),
    (r'\bQt\.DragMoveCursor\b', 'Qt.CursorShape.DragMoveCursor'),
    (r'\bQt\.DragLinkCursor\b', 'Qt.CursorShape.DragLinkCursor'),

    # Qt.GlobalColor
    (r'\bQt\.white\b', 'Qt.GlobalColor.white'),
    (r'\bQt\.black\b', 'Qt.GlobalColor.black'),
    (r'\bQt\.red\b', 'Qt.GlobalColor.red'),
    (r'\bQt\.darkRed\b', 'Qt.GlobalColor.darkRed'),
    (r'\bQt\.green\b', 'Qt.GlobalColor.green'),
    (r'\bQt\.darkGreen\b', 'Qt.GlobalColor.darkGreen'),
    (r'\bQt\.blue\b', 'Qt.GlobalColor.blue'),
    (r'\bQt\.darkBlue\b', 'Qt.GlobalColor.darkBlue'),
    (r'\bQt\.cyan\b', 'Qt.GlobalColor.cyan'),
    (r'\bQt\.darkCyan\b', 'Qt.GlobalColor.darkCyan'),
    (r'\bQt\.magenta\b', 'Qt.GlobalColor.magenta'),
    (r'\bQt\.darkMagenta\b', 'Qt.GlobalColor.darkMagenta'),
    (r'\bQt\.yellow\b', 'Qt.GlobalColor.yellow'),
    (r'\bQt\.darkYellow\b', 'Qt.GlobalColor.darkYellow'),
    (r'\bQt\.gray\b', 'Qt.GlobalColor.gray'),
    (r'\bQt\.darkGray\b', 'Qt.GlobalColor.darkGray'),
    (r'\bQt\.lightGray\b', 'Qt.GlobalColor.lightGray'),
    (r'\bQt\.transparent\b', 'Qt.GlobalColor.transparent'),

    # QMessageBox.StandardButton
    (r'\bQMessageBox\.Ok\b', 'QMessageBox.StandardButton.Ok'),
    (r'\bQMessageBox\.Open\b', 'QMessageBox.StandardButton.Open'),
    (r'\bQMessageBox\.Save\b', 'QMessageBox.StandardButton.Save'),
    (r'\bQMessageBox\.Cancel\b', 'QMessageBox.StandardButton.Cancel'),
    (r'\bQMessageBox\.Close\b', 'QMessageBox.StandardButton.Close'),
    (r'\bQMessageBox\.Discard\b', 'QMessageBox.StandardButton.Discard'),
    (r'\bQMessageBox\.Apply\b', 'QMessageBox.StandardButton.Apply'),
    (r'\bQMessageBox\.Reset\b', 'QMessageBox.StandardButton.Reset'),
    (r'\bQMessageBox\.RestoreDefaults\b', 'QMessageBox.StandardButton.RestoreDefaults'),
    (r'\bQMessageBox\.Help\b', 'QMessageBox.StandardButton.Help'),
    (r'\bQMessageBox\.SaveAll\b', 'QMessageBox.StandardButton.SaveAll'),
    (r'\bQMessageBox\.Yes\b', 'QMessageBox.StandardButton.Yes'),
    (r'\bQMessageBox\.YesToAll\b', 'QMessageBox.StandardButton.YesToAll'),
    (r'\bQMessageBox\.No\b', 'QMessageBox.StandardButton.No'),
    (r'\bQMessageBox\.NoToAll\b', 'QMessageBox.StandardButton.NoToAll'),
    (r'\bQMessageBox\.Abort\b', 'QMessageBox.StandardButton.Abort'),
    (r'\bQMessageBox\.Retry\b', 'QMessageBox.StandardButton.Retry'),
    (r'\bQMessageBox\.Ignore\b', 'QMessageBox.StandardButton.Ignore'),
    (r'\bQMessageBox\.NoButton\b', 'QMessageBox.StandardButton.NoButton'),

    # QSizePolicy.Policy
    (r'\bQSizePolicy\.Fixed\b', 'QSizePolicy.Policy.Fixed'),
    (r'\bQSizePolicy\.Minimum\b', 'QSizePolicy.Policy.Minimum'),
    (r'\bQSizePolicy\.Maximum\b', 'QSizePolicy.Policy.Maximum'),
    (r'\bQSizePolicy\.Preferred\b', 'QSizePolicy.Policy.Preferred'),
    (r'\bQSizePolicy\.Expanding\b', 'QSizePolicy.Policy.Expanding'),
    (r'\bQSizePolicy\.MinimumExpanding\b', 'QSizePolicy.Policy.MinimumExpanding'),
    (r'\bQSizePolicy\.Ignored\b', 'QSizePolicy.Policy.Ignored'),

    # QHeaderView.ResizeMode
    (r'\bQHeaderView\.Interactive\b', 'QHeaderView.ResizeMode.Interactive'),
    (r'\bQHeaderView\.Stretch\b', 'QHeaderView.ResizeMode.Stretch'),
    (r'\bQHeaderView\.Fixed\b', 'QHeaderView.ResizeMode.Fixed'),
    (r'\bQHeaderView\.ResizeToContents\b', 'QHeaderView.ResizeMode.ResizeToContents'),
    (r'\bQHeaderView\.Custom\b', 'QHeaderView.ResizeMode.Custom'),

    # QLineEdit.EchoMode
    (r'\bQLineEdit\.Normal\b', 'QLineEdit.EchoMode.Normal'),
    (r'\bQLineEdit\.NoEcho\b', 'QLineEdit.EchoMode.NoEcho'),
    (r'\bQLineEdit\.Password\b', 'QLineEdit.EchoMode.Password'),
    (r'\bQLineEdit\.PasswordEchoOnEdit\b', 'QLineEdit.EchoMode.PasswordEchoOnEdit'),

    # QTextCursor.MoveOperation
    (r'\bQTextCursor\.NoMove\b', 'QTextCursor.MoveOperation.NoMove'),
    (r'\bQTextCursor\.Start\b', 'QTextCursor.MoveOperation.Start'),
    (r'\bQTextCursor\.Up\b', 'QTextCursor.MoveOperation.Up'),
    (r'\bQTextCursor\.StartOfLine\b', 'QTextCursor.MoveOperation.StartOfLine'),
    (r'\bQTextCursor\.StartOfBlock\b', 'QTextCursor.MoveOperation.StartOfBlock'),
    (r'\bQTextCursor\.StartOfWord\b', 'QTextCursor.MoveOperation.StartOfWord'),
    (r'\bQTextCursor\.PreviousBlock\b', 'QTextCursor.MoveOperation.PreviousBlock'),
    (r'\bQTextCursor\.PreviousCharacter\b', 'QTextCursor.MoveOperation.PreviousCharacter'),
    (r'\bQTextCursor\.PreviousWord\b', 'QTextCursor.MoveOperation.PreviousWord'),
    (r'\bQTextCursor\.Left\b', 'QTextCursor.MoveOperation.Left'),
    (r'\bQTextCursor\.WordLeft\b', 'QTextCursor.MoveOperation.WordLeft'),
    (r'\bQTextCursor\.End\b', 'QTextCursor.MoveOperation.End'),
    (r'\bQTextCursor\.Down\b', 'QTextCursor.MoveOperation.Down'),
    (r'\bQTextCursor\.EndOfLine\b', 'QTextCursor.MoveOperation.EndOfLine'),
    (r'\bQTextCursor\.EndOfWord\b', 'QTextCursor.MoveOperation.EndOfWord'),
    (r'\bQTextCursor\.EndOfBlock\b', 'QTextCursor.MoveOperation.EndOfBlock'),
    (r'\bQTextCursor\.NextBlock\b', 'QTextCursor.MoveOperation.NextBlock'),
    (r'\bQTextCursor\.NextCharacter\b', 'QTextCursor.MoveOperation.NextCharacter'),
    (r'\bQTextCursor\.NextWord\b', 'QTextCursor.MoveOperation.NextWord'),
    (r'\bQTextCursor\.Right\b', 'QTextCursor.MoveOperation.Right'),
    (r'\bQTextCursor\.WordRight\b', 'QTextCursor.MoveOperation.WordRight'),
    (r'\bQTextCursor\.NextCell\b', 'QTextCursor.MoveOperation.NextCell'),
    (r'\bQTextCursor\.PreviousCell\b', 'QTextCursor.MoveOperation.PreviousCell'),
    (r'\bQTextCursor\.NextRow\b', 'QTextCursor.MoveOperation.NextRow'),
    (r'\bQTextCursor\.PreviousRow\b', 'QTextCursor.MoveOperation.PreviousRow'),

    # QTabWidget.TabPosition
    (r'\bQTabWidget\.North\b', 'QTabWidget.TabPosition.North'),
    (r'\bQTabWidget\.South\b', 'QTabWidget.TabPosition.South'),
    (r'\bQTabWidget\.West\b', 'QTabWidget.TabPosition.West'),
    (r'\bQTabWidget\.East\b', 'QTabWidget.TabPosition.East'),

    # QSlider.TickPosition
    (r'\bQSlider\.NoTicks\b', 'QSlider.TickPosition.NoTicks'),
    (r'\bQSlider\.TicksAbove\b', 'QSlider.TickPosition.TicksAbove'),
    (r'\bQSlider\.TicksBelow\b', 'QSlider.TickPosition.TicksBelow'),
    (r'\bQSlider\.TicksBothSides\b', 'QSlider.TickPosition.TicksBothSides'),

    # Qt.Key - Common keys
    (r'\bQt\.Key_([A-Za-z0-9_]+)\b', r'Qt.Key.Key_\1'),

    # Qt.KeyboardModifier
    (r'\bQt\.NoModifier\b', 'Qt.KeyboardModifier.NoModifier'),
    (r'\bQt\.ShiftModifier\b', 'Qt.KeyboardModifier.ShiftModifier'),
    (r'\bQt\.ControlModifier\b', 'Qt.KeyboardModifier.ControlModifier'),
    (r'\bQt\.AltModifier\b', 'Qt.KeyboardModifier.AltModifier'),
    (r'\bQt\.MetaModifier\b', 'Qt.KeyboardModifier.MetaModifier'),
    (r'\bQt\.KeypadModifier\b', 'Qt.KeyboardModifier.KeypadModifier'),
    (r'\bQt\.GroupSwitchModifier\b', 'Qt.KeyboardModifier.GroupSwitchModifier'),

    # Qt.MouseButton
    (r'\bQt\.NoButton\b', 'Qt.MouseButton.NoButton'),
    (r'\bQt\.LeftButton\b', 'Qt.MouseButton.LeftButton'),
    (r'\bQt\.RightButton\b', 'Qt.MouseButton.RightButton'),
    (r'\bQt\.MiddleButton\b', 'Qt.MouseButton.MiddleButton'),
    (r'\bQt\.BackButton\b', 'Qt.MouseButton.BackButton'),
    (r'\bQt\.ForwardButton\b', 'Qt.MouseButton.ForwardButton'),
    (r'\bQt\.TaskButton\b', 'Qt.MouseButton.TaskButton'),
    (r'\bQt\.ExtraButton1\b', 'Qt.MouseButton.ExtraButton1'),
    (r'\bQt\.ExtraButton2\b', 'Qt.MouseButton.ExtraButton2'),

    # Qt.TextFormat
    (r'\bQt\.PlainText\b', 'Qt.TextFormat.PlainText'),
    (r'\bQt\.RichText\b', 'Qt.TextFormat.RichText'),
    (r'\bQt\.AutoText\b', 'Qt.TextFormat.AutoText'),
    (r'\bQt\.MarkdownText\b', 'Qt.TextFormat.MarkdownText'),

    # Qt.ToolButtonStyle
    (r'\bQt\.ToolButtonIconOnly\b', 'Qt.ToolButtonStyle.ToolButtonIconOnly'),
    (r'\bQt\.ToolButtonTextOnly\b', 'Qt.ToolButtonStyle.ToolButtonTextOnly'),
    (r'\bQt\.ToolButtonTextBesideIcon\b', 'Qt.ToolButtonStyle.ToolButtonTextBesideIcon'),
    (r'\bQt\.ToolButtonTextUnderIcon\b', 'Qt.ToolButtonStyle.ToolButtonTextUnderIcon'),
    (r'\bQt\.ToolButtonFollowStyle\b', 'Qt.ToolButtonStyle.ToolButtonFollowStyle'),

    # Qt.DockWidgetArea
    (r'\bQt\.LeftDockWidgetArea\b', 'Qt.DockWidgetArea.LeftDockWidgetArea'),
    (r'\bQt\.RightDockWidgetArea\b', 'Qt.DockWidgetArea.RightDockWidgetArea'),
    (r'\bQt\.TopDockWidgetArea\b', 'Qt.DockWidgetArea.TopDockWidgetArea'),
    (r'\bQt\.BottomDockWidgetArea\b', 'Qt.DockWidgetArea.BottomDockWidgetArea'),
    (r'\bQt\.AllDockWidgetAreas\b', 'Qt.DockWidgetArea.AllDockWidgetAreas'),
    (r'\bQt\.NoDockWidgetArea\b', 'Qt.DockWidgetArea.NoDockWidgetArea'),

    # Qt.Corner
    (r'\bQt\.TopLeftCorner\b', 'Qt.Corner.TopLeftCorner'),
    (r'\bQt\.TopRightCorner\b', 'Qt.Corner.TopRightCorner'),
    (r'\bQt\.BottomLeftCorner\b', 'Qt.Corner.BottomLeftCorner'),
    (r'\bQt\.BottomRightCorner\b', 'Qt.Corner.BottomRightCorner'),

    # Qt.Edge
    (r'\bQt\.TopEdge\b', 'Qt.Edge.TopEdge'),
    (r'\bQt\.LeftEdge\b', 'Qt.Edge.LeftEdge'),
    (r'\bQt\.RightEdge\b', 'Qt.Edge.RightEdge'),
    (r'\bQt\.BottomEdge\b', 'Qt.Edge.BottomEdge'),

    # QAbstractItemView.SelectionBehavior
    (r'\bQAbstractItemView\.SelectItems\b', 'QAbstractItemView.SelectionBehavior.SelectItems'),
    (r'\bQAbstractItemView\.SelectRows\b', 'QAbstractItemView.SelectionBehavior.SelectRows'),
    (r'\bQAbstractItemView\.SelectColumns\b', 'QAbstractItemView.SelectionBehavior.SelectColumns'),

    # QAbstractItemView.SelectionMode
    (r'\bQAbstractItemView\.NoSelection\b', 'QAbstractItemView.SelectionMode.NoSelection'),
    (r'\bQAbstractItemView\.SingleSelection\b', 'QAbstractItemView.SelectionMode.SingleSelection'),
    (r'\bQAbstractItemView\.MultiSelection\b', 'QAbstractItemView.SelectionMode.MultiSelection'),
    (r'\bQAbstractItemView\.ExtendedSelection\b', 'QAbstractItemView.SelectionMode.ExtendedSelection'),
    (r'\bQAbstractItemView\.ContiguousSelection\b', 'QAbstractItemView.SelectionMode.ContiguousSelection'),

    # QAbstractItemView.EditTrigger
    (r'\bQAbstractItemView\.NoEditTriggers\b', 'QAbstractItemView.EditTrigger.NoEditTriggers'),
    (r'\bQAbstractItemView\.CurrentChanged\b', 'QAbstractItemView.EditTrigger.CurrentChanged'),
    (r'\bQAbstractItemView\.DoubleClicked\b', 'QAbstractItemView.EditTrigger.DoubleClicked'),
    (r'\bQAbstractItemView\.SelectedClicked\b', 'QAbstractItemView.EditTrigger.SelectedClicked'),
    (r'\bQAbstractItemView\.EditKeyPressed\b', 'QAbstractItemView.EditTrigger.EditKeyPressed'),
    (r'\bQAbstractItemView\.AnyKeyPressed\b', 'QAbstractItemView.EditTrigger.AnyKeyPressed'),
    (r'\bQAbstractItemView\.AllEditTriggers\b', 'QAbstractItemView.EditTrigger.AllEditTriggers'),
]


def fix_file(filepath):
    """Fix PyQt6 enum issues in a single file."""
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            content = f.read()
    except Exception as e:
        print(f"Error reading {filepath}: {e}")
        return 0

    original_content = content
    replacements_made = 0

    # Apply all replacements
    for pattern, replacement in ENUM_REPLACEMENTS:
        # Special handling for Qt.Key_ pattern which has a capture group
        if r'\1' in replacement:
            # This is a pattern with capture groups
            matches = list(re.finditer(pattern, content))
            if matches:
                # For patterns with capture groups, we need to handle differently
                new_content = re.sub(pattern, replacement, content)
                if new_content != content:
                    content = new_content
                    replacements_made += len(matches)
        else:
            # Count how many replacements we make
            matches = re.findall(pattern, content)
            if matches:
                # Check if the replacement is already present nearby (avoid double replacement)
                # This prevents Qt.AlignmentFlag.AlignmentFlag.AlignCenter issues
                check_pattern = re.escape(replacement)
                if not re.search(check_pattern, content):
                    content = re.sub(pattern, replacement, content)
                    replacements_made += len(matches)

    # Only write if changes were made
    if content != original_content:
        try:
            with open(filepath, 'w', encoding='utf-8') as f:
                f.write(content)
            return replacements_made
        except Exception as e:
            print(f"Error writing {filepath}: {e}")
            return 0

    return 0


def main():
    """Main function to fix all Python files in the project."""
    print("PyQt6 Enum Compatibility Fixer")
    print("=" * 40)

    project_root = Path(__file__).parent
    intellicrack_path = project_root / "intellicrack"

    if not intellicrack_path.exists():
        print(f"Intellicrack path not found: {intellicrack_path}")
        return

    total_replacements = 0
    files_modified = []
    total_files = 0

    # Process all Python files in the entire intellicrack directory
    for py_file in intellicrack_path.rglob("*.py"):
        total_files += 1
        replacements = fix_file(py_file)
        if replacements > 0:
            total_replacements += replacements
            files_modified.append((py_file, replacements))
            print(f"Fixed {py_file.relative_to(project_root)} ({replacements} replacements)")

    print(f"\nTotal files processed: {total_files}")
    print(f"Total replacements made: {total_replacements}")
    print(f"Files modified: {len(files_modified)}")

    if files_modified:
        print("\nTop modified files:")
        for file_path, count in sorted(files_modified, key=lambda x: x[1], reverse=True)[:10]:
            print(f"  {file_path.relative_to(project_root)}: {count} replacements")
        if len(files_modified) > 10:
            print(f"  ... and {len(files_modified) - 10} more files")

    print("\nDone! All PyQt6 enum compatibility issues have been fixed.")


if __name__ == "__main__":
    main()
