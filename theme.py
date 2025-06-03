# theme.py

DARK_STYLE = """
QMainWindow {
    background-color: #2e2e2e;
    color: #f0f0f0;
}

QMenuBar {
    background-color: #3c3c3c;
    color: #f0f0f0;
    border-bottom: 1px solid #555555;
}
QMenuBar::item {
    background-color: transparent;
    padding: 4px 10px;
}
QMenuBar::item:selected {
    background-color: #5a5a5a;
}
QMenuBar::item:pressed {
    background-color: #4a4a4a;
}

QMenu {
    background-color: #3c3c3c;
    color: #f0f0f0;
    border: 1px solid #555555;
    padding: 2px;
}
QMenu::item {
    padding: 4px 20px 4px 20px;
}
QMenu::item:selected {
    background-color: #5a5a5a;
}
QMenu::item:disabled {
    color: #777777;
}
QMenu::separator {
    height: 1px;
    background-color: #555555;
    margin: 4px 0px;
}

/* === Other Widgets === */
QLabel {
    color: #f0f0f0;
    padding-top: 4px;
}

QComboBox { /* Style for Monitoring Level dropdown */
    background-color: #505050;
    color: #f0f0f0;
    border: 1px solid #666666;
    padding: 4px;
    min-width: 120px;
    selection-background-color: #5a5a5a; /* background of selected item */
}
QComboBox::drop-down { /* arrow button */
    border: 1px solid #666666;
    background-color: #5a5a5a;
}
QComboBox::down-arrow {
     width: 10px;
     height: 10px;
}
QComboBox QAbstractItemView { /* dropdown list */
    background-color: #3c3c3c;
    color: #f0f0f0;
    border: 1px solid #555555;
    selection-background-color: #5a5a5a;
}


QLineEdit {
    background-color: #505050;
    color: #f0f0f0;
    border: 1px solid #666666;
    padding: 4px;
    font-size: 10pt;
}

QPushButton {
    background-color: #5a5a5a;
    color: #f0f0f0;
    border: 1px solid #666666;
    padding: 4px 8px;
    min-width: 60px;
}

QPushButton:hover {
    background-color: #6a6a6a;
    border: 1px solid #777777;
}

QPushButton:pressed {
    background-color: #4a4a4a;
}

QTableWidget {
    background-color: #3c3c3c;
    color: #f0f0f0;
    gridline-color: #555555;
    alternate-background-color: #454545;
    selection-background-color: #5a5a5a;
    selection-color: #f0f0f0;
    border: 1px solid #555555;
}

QHeaderView::section {
    background-color: #4a4a4a;
    color: #f0f0f0;
    padding: 4px;
    border: 1px solid #555555;
}

QTableCornerButton::section {
    background-color: #4a4a4a;
    border: 1px solid #555555;
}

QStatusBar {
    background-color: #2e2e2e;
    color: #f0f0f0;
}

QStatusBar::item {
    border: none;
}
"""