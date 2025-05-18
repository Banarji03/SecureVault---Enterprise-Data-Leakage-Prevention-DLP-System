from PyQt5.QtWidgets import *
from PyQt5.QtCore import *
from PyQt5.QtGui import *
import sys
from datetime import datetime
from utils.logger import Logger

class Dashboard(QMainWindow):
    def __init__(self, policy_engine, detection_engine):
        super().__init__()
        self.policy_engine = policy_engine
        self.detection_engine = detection_engine
        self.logger = Logger()
        
        # Add notification system
        self.notification_timer = QTimer()
        self.notification_timer.timeout.connect(self.clear_notification)
        
        # Connect detection engine signals if available
        if hasattr(detection_engine, 'prediction_made'):
            detection_engine.prediction_made.connect(self.handle_prediction)
            
        self.init_ui()

    def init_ui(self):
        self.setWindowTitle('SecureVault DLP Dashboard')
        self.setGeometry(100, 100, 1200, 800)

        # Create main widget and layout
        main_widget = QWidget()
        self.setCentralWidget(main_widget)
        layout = QVBoxLayout(main_widget)

        # Create tab widget
        tabs = QTabWidget()
        layout.addWidget(tabs)

        # Add tabs
        tabs.addTab(self.create_incidents_tab(), 'Incidents')
        tabs.addTab(self.create_policies_tab(), 'Policies')
        tabs.addTab(self.create_monitoring_tab(), 'Monitoring')
        tabs.addTab(self.create_reports_tab(), 'Reports')

        # Status bar
        self.statusBar().showMessage('System running')

    def create_incidents_tab(self):
        widget = QWidget()
        layout = QVBoxLayout(widget)

        # Incidents table
        self.incidents_table = QTableWidget()
        self.incidents_table.setColumnCount(6)
        self.incidents_table.setHorizontalHeaderLabels(
            ['Time', 'Type', 'Severity', 'Source', 'Status', 'Actions'])
        layout.addWidget(self.incidents_table)

        # Refresh button
        refresh_btn = QPushButton('Refresh')
        refresh_btn.clicked.connect(self.refresh_incidents)
        layout.addWidget(refresh_btn)

        return widget

    def create_policies_tab(self):
        widget = QWidget()
        layout = QVBoxLayout(widget)

        # Policy list
        self.policy_list = QListWidget()
        layout.addWidget(self.policy_list)

        # Add policy button
        add_policy_btn = QPushButton('Add Policy')
        add_policy_btn.clicked.connect(self.show_add_policy_dialog)
        layout.addWidget(add_policy_btn)

        return widget

    def create_monitoring_tab(self):
        widget = QWidget()
        layout = QVBoxLayout(widget)

        # Monitoring status
        group_box = QGroupBox('Monitoring Status')
        status_layout = QVBoxLayout()

        self.file_monitor_status = QLabel('File Monitor: Active')
        self.clipboard_monitor_status = QLabel('Clipboard Monitor: Active')
        self.screen_monitor_status = QLabel('Screen Monitor: Active')

        status_layout.addWidget(self.file_monitor_status)
        status_layout.addWidget(self.clipboard_monitor_status)
        status_layout.addWidget(self.screen_monitor_status)

        group_box.setLayout(status_layout)
        layout.addWidget(group_box)

        # Add DLP Model Status and Configuration
        model_group = QGroupBox('DLP Model Configuration')
        model_layout = QVBoxLayout()

        # Model info
        self.model_status = QLabel('Model: Active')
        model_layout.addWidget(self.model_status)

        # Confidence threshold slider
        threshold_layout = QHBoxLayout()
        threshold_layout.addWidget(QLabel('Confidence Threshold:'))
        self.confidence_slider = QSlider(Qt.Horizontal)
        self.confidence_slider.setMinimum(50)
        self.confidence_slider.setMaximum(95)
        self.confidence_slider.setValue(85)
        self.confidence_slider.valueChanged.connect(self.update_confidence_threshold)
        self.confidence_value = QLabel('0.85')
        threshold_layout.addWidget(self.confidence_slider)
        threshold_layout.addWidget(self.confidence_value)
        model_layout.addLayout(threshold_layout)

        # Pattern selection
        pattern_group = QGroupBox('Detection Patterns')
        pattern_layout = QVBoxLayout()
        self.pattern_checkboxes = {}
        patterns = ['SSN', 'Credit Cards', 'API Keys', 'Passwords', 'Email Addresses']
        for pattern in patterns:
            cb = QCheckBox(pattern)
            cb.setChecked(True)
            cb.stateChanged.connect(self.update_patterns)
            self.pattern_checkboxes[pattern] = cb
            pattern_layout.addWidget(cb)
        pattern_group.setLayout(pattern_layout)
        model_layout.addWidget(pattern_group)

        # Last prediction
        self.last_prediction = QLabel('Last Prediction: None')
        model_layout.addWidget(self.last_prediction)

        model_group.setLayout(model_layout)
        layout.addWidget(model_group)

        return widget

    def update_confidence_threshold(self):
        value = self.confidence_slider.value() / 100
        self.confidence_value.setText(f"{value:.2f}")
        if hasattr(self.detection_engine, 'set_confidence_threshold'):
            self.detection_engine.set_confidence_threshold(value)
            # Update status bar
            self.statusBar().showMessage(f"Confidence threshold updated to {value:.2f}")

    def update_patterns(self):
        enabled_patterns = [pattern for pattern, cb in self.pattern_checkboxes.items() 
                          if cb.isChecked()]
        if hasattr(self.detection_engine, 'set_enabled_patterns'):
            self.detection_engine.set_enabled_patterns(enabled_patterns)

    def create_incidents_tab(self):
        widget = QWidget()
        layout = QVBoxLayout(widget)

        # Incidents table
        self.incidents_table = QTableWidget()
        self.incidents_table.setColumnCount(7)  # Added confidence column
        self.incidents_table.setHorizontalHeaderLabels(
            ['Time', 'Type', 'Severity', 'Source', 'Status', 'Confidence', 'Actions'])
        layout.addWidget(self.incidents_table)

        # Refresh button
        refresh_btn = QPushButton('Refresh')
        refresh_btn.clicked.connect(self.refresh_incidents)
        layout.addWidget(refresh_btn)

        return widget

    def refresh_incidents(self):
        incidents = self.policy_engine.db.get_incidents()
        self.incidents_table.setRowCount(len(incidents))
        for i, incident in enumerate(incidents):
            self.incidents_table.setItem(i, 0, QTableWidgetItem(incident['timestamp']))
            self.incidents_table.setItem(i, 1, QTableWidgetItem(incident['incident_type']))
            self.incidents_table.setItem(i, 2, QTableWidgetItem(incident['severity']))
            self.incidents_table.setItem(i, 3, QTableWidgetItem(incident['file_path']))
            self.incidents_table.setItem(i, 4, QTableWidgetItem(incident['status']))
            
            # Add confidence score
            confidence = incident.get('confidence', 'N/A')
            if isinstance(confidence, float):
                confidence = f"{confidence:.3f}"
            self.incidents_table.setItem(i, 5, QTableWidgetItem(str(confidence)))

            # Add actions button
            actions_btn = QPushButton('View')
            actions_btn.clicked.connect(lambda checked, row=i: self.show_incident_details(row))
            self.incidents_table.setCellWidget(i, 6, actions_btn)

    def show_incident_details(self, row):
        dialog = QDialog(self)
        dialog.setWindowTitle('Incident Details')
        dialog.setMinimumWidth(600)
        layout = QVBoxLayout(dialog)

        # Get incident data
        incident = {
            'timestamp': self.incidents_table.item(row, 0).text(),
            'type': self.incidents_table.item(row, 1).text(),
            'severity': self.incidents_table.item(row, 2).text(),
            'source': self.incidents_table.item(row, 3).text(),
            'status': self.incidents_table.item(row, 4).text(),
            'confidence': self.incidents_table.item(row, 5).text()
        }

        # Create details form
        form = QFormLayout()
        for key, value in incident.items():
            form.addRow(f"{key.title()}:", QLabel(value))

        # Add pattern matches if available
        if hasattr(self.detection_engine, 'get_pattern_matches'):
            matches = self.detection_engine.get_pattern_matches(incident['source'])
            if matches:
                patterns_text = QTextEdit()
                patterns_text.setPlainText('\n'.join(matches))
                patterns_text.setReadOnly(True)
                form.addRow("Pattern Matches:", patterns_text)

        layout.addLayout(form)

        # Close button
        close_btn = QPushButton('Close')
        close_btn.clicked.connect(dialog.close)
        layout.addWidget(close_btn)

        dialog.exec_()

    def create_reports_tab(self):
        widget = QWidget()
        layout = QVBoxLayout(widget)

        # Date range selection
        date_group = QGroupBox('Date Range')
        date_layout = QHBoxLayout()
        self.start_date = QDateEdit()
        self.end_date = QDateEdit()
        self.start_date.setDate(QDate.currentDate().addDays(-30))
        self.end_date.setDate(QDate.currentDate())
        date_layout.addWidget(QLabel('From:'))
        date_layout.addWidget(self.start_date)
        date_layout.addWidget(QLabel('To:'))
        date_layout.addWidget(self.end_date)
        date_group.setLayout(date_layout)
        layout.addWidget(date_group)

        # Report type selection
        type_group = QGroupBox('Report Type')
        type_layout = QVBoxLayout()
        self.report_types = {
            'incident_summary': QCheckBox('Incident Summary'),
            'pattern_analysis': QCheckBox('Pattern Analysis'),
            'model_performance': QCheckBox('Model Performance'),
            'trend_analysis': QCheckBox('Trend Analysis')
        }
        for cb in self.report_types.values():
            cb.setChecked(True)
            type_layout.addWidget(cb)
        type_group.setLayout(type_layout)
        layout.addWidget(type_group)

        # Schedule report
        schedule_group = QGroupBox('Report Schedule')
        schedule_layout = QHBoxLayout()
        self.schedule_enabled = QCheckBox('Enable Scheduled Reports')
        schedule_layout.addWidget(self.schedule_enabled)
        self.schedule_interval = QComboBox()
        self.schedule_interval.addItems(['Daily', 'Weekly', 'Monthly'])
        schedule_layout.addWidget(self.schedule_interval)
        schedule_group.setLayout(schedule_layout)
        layout.addWidget(schedule_group)

        # Export options
        export_group = QGroupBox('Export Options')
        export_layout = QHBoxLayout()
        self.export_format = QComboBox()
        self.export_format.addItems(['PDF', 'CSV', 'HTML'])
        export_layout.addWidget(QLabel('Format:'))
        export_layout.addWidget(self.export_format)
        export_group.setLayout(export_layout)
        layout.addWidget(export_group)

        # Buttons layout
        button_layout = QHBoxLayout()
        generate_btn = QPushButton('Generate Report')
        generate_btn.clicked.connect(self.generate_report)
        export_btn = QPushButton('Export Report')
        export_btn.clicked.connect(self.export_report)
        button_layout.addWidget(generate_btn)
        button_layout.addWidget(export_btn)
        layout.addLayout(button_layout)

        # Report preview with tabs
        preview_group = QGroupBox('Report Preview')
        preview_layout = QVBoxLayout()
        self.preview_tabs = QTabWidget()
        
        # Text preview
        self.report_preview = QTextEdit()
        self.report_preview.setReadOnly(True)
        self.preview_tabs.addTab(self.report_preview, 'Text')
        
        # Chart preview
        self.chart_widget = QWidget()
        self.chart_layout = QVBoxLayout(self.chart_widget)
        self.preview_tabs.addTab(self.chart_widget, 'Charts')
        
        preview_layout.addWidget(self.preview_tabs)
        preview_group.setLayout(preview_layout)
        layout.addWidget(preview_group)

        return widget

    def export_report(self):
        format = self.export_format.currentText()
        filename, _ = QFileDialog.getSaveFileName(
            self, 'Export Report',
            f'dlp_report_{datetime.now().strftime("%Y%m%d")}.{format.lower()}',
            f'{format} Files (*.{format.lower()})'
        )
        
        if filename:
            try:
                if format == 'PDF':
                    self.export_to_pdf(filename)
                elif format == 'CSV':
                    self.export_to_csv(filename)
                elif format == 'HTML':
                    self.export_to_html(filename)
                self.statusBar().showMessage(f'Report exported to {filename}')
            except Exception as e:
                self.logger.error(f'Error exporting report: {str(e)}')
                QMessageBox.critical(self, 'Export Error', f'Failed to export report: {str(e)}')

    def update_charts(self, report_data):
        # Clear existing charts
        for i in reversed(range(self.chart_layout.count())): 
            self.chart_layout.itemAt(i).widget().setParent(None)
        
        # Incident trend chart
        if report_data.get('trends'):
            trend_chart = QChart()
            trend_series = QLineSeries()
            for trend in report_data['trends']:
                trend_series.append(QPoint(trend['timestamp'], trend['count']))
            trend_chart.addSeries(trend_series)
            trend_chart.setTitle('Incident Trends')
            self.chart_layout.addWidget(QChartView(trend_chart))
        
        # Pattern distribution chart
        if report_data.get('pattern_stats'):
            pattern_chart = QChart()
            pattern_series = QPieSeries()
            for pattern, count in report_data['pattern_stats'].items():
                pattern_series.append(pattern, count)
            pattern_chart.addSeries(pattern_series)
            pattern_chart.setTitle('Pattern Distribution')
            self.chart_layout.addWidget(QChartView(pattern_chart))

    def schedule_report(self):
        if not self.schedule_enabled.isChecked():
            return
            
        interval = self.schedule_interval.currentText()
        schedule_time = QTime.currentTime()
        
        if interval == 'Daily':
            self.schedule_timer = QTimer(self)
            self.schedule_timer.timeout.connect(self.generate_scheduled_report)
            # Set timer for next day
            msec_until_next = QTime(schedule_time).msecsTo(QTime(0, 0, 0).addSecs(24*60*60))
            self.schedule_timer.start(msec_until_next)
        elif interval == 'Weekly':
            # Similar logic for weekly reports
            pass
        elif interval == 'Monthly':
            # Similar logic for monthly reports
            pass

    def generate_scheduled_report(self):
        self.generate_report()
        # Auto export if configured
        if hasattr(self, 'auto_export') and self.auto_export.isChecked():
            self.export_report()

    def generate_report(self):
        start_date = self.start_date.date().toPyDate()
        end_date = self.end_date.date().toPyDate()
        
        report_content = []
        
        # Incident Summary
        if self.report_types['incident_summary'].isChecked():
            # Get all incidents and filter by date in memory
            incidents = self.policy_engine.db.get_incidents()
            incidents = [i for i in incidents
                        if start_date <= datetime.fromisoformat(i['timestamp']).date() <= end_date]
            total = len(incidents)
            sensitive = sum(1 for i in incidents if i['severity'] == 'high')
            report_content.append(
                f"Incident Summary (Total: {total}):\n"
                f"- High Severity: {sensitive}\n"
                f"- Detection Rate: {(sensitive/total*100 if total > 0 else 0):.1f}%\n"
            )

        # Pattern Analysis
        if self.report_types['pattern_analysis'].isChecked():
            pattern_stats = self.detection_engine.get_pattern_stats(start_date, end_date)
            report_content.append("\nPattern Detection Statistics:")
            for pattern, count in pattern_stats.items():
                report_content.append(f"- {pattern}: {count} detections")

        # Model Performance
        if self.report_types['model_performance'].isChecked():
            performance = self.detection_engine.get_model_performance(start_date, end_date)
            report_content.append(
                f"\nModel Performance Metrics:\n"
                f"- Accuracy: {performance.get('accuracy', 0):.3f}\n"
                f"- Precision: {performance.get('precision', 0):.3f}\n"
                f"- Recall: {performance.get('recall', 0):.3f}\n"
                f"- F1 Score: {performance.get('f1', 0):.3f}"
            )

        # Trend Analysis
        if self.report_types['trend_analysis'].isChecked():
            trends = self.detection_engine.get_detection_trends(start_date, end_date)
            report_content.append("\nDetection Trends:")
            for trend in trends:
                report_content.append(
                    f"- {trend['period']}: "
                    f"{trend['count']} incidents "
                    f"({trend['change']:+.1f}% change)"
                )

        # Update preview
        self.report_preview.setPlainText('\n'.join(report_content))
        
        # Log report generation
        self.logger.info(f"Generated report from {start_date} to {end_date}")

    def run(self):
        self.show()
        self.refresh_incidents()

    def handle_prediction(self, prediction_data):
        # Update last prediction label
        prediction = prediction_data.get('prediction', 'unknown')
        confidence = prediction_data.get('confidence', 0.0)
        self.last_prediction.setText(
            f"Last Prediction: {prediction} (confidence: {confidence:.3f})")
        
        # Show notification for sensitive content
        if prediction == 'sensitive' and confidence >= self.confidence_slider.value() / 100:
            self.show_notification(f"Sensitive content detected! (confidence: {confidence:.3f})")

    def show_notification(self, message):
        notification = QDialog(self, Qt.FramelessWindowHint | Qt.WindowStaysOnTopHint)
        notification.setStyleSheet(
            "background-color: #ffebee; color: #c62828; padding: 10px; border: 1px solid #ef5350;")
        
        # Create notification layout
        layout = QVBoxLayout(notification)
        
        # Add warning icon and message
        msg_layout = QHBoxLayout()
        icon_label = QLabel()
        icon_label.setPixmap(self.style().standardPixmap(QStyle.SP_MessageBoxWarning))
        msg_layout.addWidget(icon_label)
        msg_layout.addWidget(QLabel(message))
        layout.addLayout(msg_layout)
        
        # Position notification
        screen = QDesktopWidget().screenGeometry()
        notification.move(screen.width() - notification.width() - 20,
                         screen.height() - notification.height() - 20)
        
        # Show notification and start timer
        notification.show()
        self.notification_timer.start(5000)  # Hide after 5 seconds
        self.current_notification = notification

    def clear_notification(self):
        if hasattr(self, 'current_notification'):
            self.current_notification.close()
        self.notification_timer.stop()


    def show_add_policy_dialog(self):
        dialog = QDialog(self)
        dialog.setWindowTitle('Add New Policy')
        dialog.setModal(True)
        
        layout = QFormLayout(dialog)
        
        # Policy name input
        name_input = QLineEdit()
        layout.addRow('Policy Name:', name_input)
        
        # Policy type selection
        type_combo = QComboBox()
        type_combo.addItems(['Data Transfer', 'Content Access', 'Device Usage'])
        layout.addRow('Policy Type:', type_combo)
        
        # Policy description
        desc_input = QTextEdit()
        layout.addRow('Description:', desc_input)
        
        # Action selection
        action_combo = QComboBox()
        action_combo.addItems(['Block', 'Alert', 'Log'])
        layout.addRow('Action:', action_combo)
        
        # Buttons
        button_box = QDialogButtonBox(
            QDialogButtonBox.Ok | QDialogButtonBox.Cancel
        )
        button_box.accepted.connect(dialog.accept)
        button_box.rejected.connect(dialog.reject)
        layout.addRow(button_box)
        
        if dialog.exec_() == QDialog.Accepted:
            # Add the new policy
            self.policy_engine.add_policy({
                'name': name_input.text(),
                'type': type_combo.currentText(),
                'description': desc_input.toPlainText(),
                'action': action_combo.currentText(),
                'created_at': datetime.now().isoformat()
            })
            self.refresh_policies()

    def refresh_policies(self):
        self.policy_list.clear()
        policies = self.policy_engine.get_policies()
        for policy in policies:
            item = QListWidgetItem(f"{policy['name']} - {policy['type']}")
            item.setData(Qt.UserRole, policy)
            self.policy_list.addItem(item)