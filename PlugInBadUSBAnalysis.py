# coding=utf-8
# 28.01.2025
import os
import codecs
from java.lang import System
from java.util.logging import Level
from org.sleuthkit.datamodel import TskData
from org.sleuthkit.autopsy.casemodule import Case
from org.sleuthkit.autopsy.coreutils import Logger
from org.sleuthkit.autopsy.report import GeneralReportModuleAdapter
from org.sleuthkit.autopsy.report.ReportProgressPanel import ReportStatus
from org.sleuthkit.datamodel import BlackboardArtifact
from org.sleuthkit.datamodel import BlackboardAttribute
from java.time import Instant, ZoneId, ZonedDateTime
from java.time.format import DateTimeFormatter
from org.sleuthkit.autopsy.casemodule.services import Blackboard
from java.util import Arrays
from org.sleuthkit.datamodel import Score
from org.sleuthkit.datamodel import ReadContentInputStream
import jarray


# Definiert die Reportmodul-Klasse für CSV-Berichte
class CSVReportModule(GeneralReportModuleAdapter):
    # Name des Moduls für den Bericht
    moduleName = "BadUSB Investigation Module"
    # Logger-Instanz wird später initialisiert
    _logger = None

    # Log-Methode für Fehlerprotokollierung
    def log(self, level, msg):
        # Überprüft, ob der Logger bereits existiert
        if _logger == None:
            # Initialisiert den Logger mit dem Modulnamen
            _logger = Logger.getLogger(self.moduleName)
        # Loggt die Nachricht mit der Log-Stufe und dem Stack-Trace
        self._logger.logp(level, self.__class__.__name__, inspect.stack()[1][3], msg)


    # Gibt den Namen des Moduls zurück
    def getName(self):
        return self.moduleName

    # Gibt eine kurze Beschreibung des Moduls zurück
    def getDescription(self):
        return "This module identifies and analyzes artifacts related to potential BadUSB attacks. " \
               "It extracts USB device information and program executions into a CSV report and " \
               "marks relevant Files and Windows Event Logs as interesting files in the Blackboard."    # Beschreibt die Funktion des Moduls

    # Gibt den relativen Pfad der Ausgabedatei zurück
    def getRelativeFilePath(self):
        return "BadUSB_Activity_Report.csv"    # Der Dateiname des Berichts

    # Hauptmethode zur Berichtserstellung
    def generateReport(self, reportSettings, progressBar):
        # Öffnet die Ausgabedatei
        fileName = os.path.join(reportSettings.getReportDirectoryPath(), self.getRelativeFilePath())
        # Öffnet die Datei im Schreibmodus mit UTF-8 Encoding
        report = codecs.open(fileName, "w", "utf-8")

        # Liste von verdächtigen Programmen
        suspected_executables = [
            "ipconfig.exe", "whoami.exe", "netstat.exe", "ping.exe",
            "nslookup.exe", "tasklist.exe", "dir.exe",
            "curl.exe", "wget.exe", "tar.exe", "echo.exe", "cmd.exe", "powershell.exe", "mpcmdrun.exe", "windowsterminal.exe",
            "openconsole.exe"
        ]

        # Abfrage der Datenbank nach USB-Gerät- und Programmausführungs-Artefakten
        sleuthkitCase = Case.getCurrentCase().getSleuthkitCase()
        usb_files = sleuthkitCase.getBlackboardArtifacts(BlackboardArtifact.ARTIFACT_TYPE.TSK_DEVICE_ATTACHED)   # Holt USB-Artifakts
        program_files = sleuthkitCase.getBlackboardArtifacts(BlackboardArtifact.ARTIFACT_TYPE.TSK_PROG_RUN)     # Holt Programmausführungs-Artifakte

        # Sortiert die Programmausführungs-Artefakte nach Zeitstempel
        sorted_program_files = sorted(program_files, key=lambda program_file: program_file.getAttribute(
            BlackboardAttribute.Type(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_DATETIME)).getValueLong() if program_file.getAttribute(
            BlackboardAttribute.Type(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_DATETIME)) else 0)

        # Initialisiert die Fortschrittsanzeige
        progressBar.setIndeterminate(False)                 # Setzt die Fortschrittsanzeige auf bestimmbar
        progressBar.start()                                 # Startet die Fortschrittsanzeige
        progressBar.setMaximumProgress(len(usb_files))      # Setzt den maximalen Fortschritt auf die Anzahl der USB-Dateien

        # Iteriert durch die USB-Artifakte
        for usb_file in usb_files:
            # Extrahiert die USB-Gerätedaten
            device_id = ""
            timestamp = ""
            device_make = ""
            device_model = ""
            data_source = usb_file.getUniquePath()      # Holt den Pfad der Datenquelle (USB)

            # Holt die Device-ID und setzt die Device-ID, falls vorhanden
            device_id_attr = usb_file.getAttribute(
                BlackboardAttribute.Type(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_DEVICE_ID))
            device_id = device_id_attr.getValueString() if device_id_attr else ""

            # Holt den Zeitstempel und setzt den Zeitstempel, falls vorhanden
            timestamp_attr = usb_file.getAttribute(
                BlackboardAttribute.Type(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_DATETIME))
            timestamp = timestamp_attr.getValueLong() if timestamp_attr else ""
            local_time = ""         # Initialisiert eine leere lokale Zeit

            # Wenn der Zeitstempel vorhanden ist
            if timestamp:
                utc_time = Instant.ofEpochSecond(timestamp)     # Konvertiert den Zeitstempel in UTC
                zone_id = ZoneId.of("Europe/Berlin")            # Setzt die Zeitzone auf Berlin
                local_time = ZonedDateTime.ofInstant(utc_time, zone_id)     # Wandelt die Zeit in die lokale Zeit um
                timestamp = local_time.format(DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss.SSS"))   # Formatiert die Zeit

            # Holt die Marke des Geräts und setzt die Marke, falls vorhanden
            device_make_attr = usb_file.getAttribute(
                BlackboardAttribute.Type(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_DEVICE_MAKE))
            device_make = device_make_attr.getValueString() if device_make_attr else ""

            # Holt das Modell des Geräts und setzt das Modell, falls vorhanden
            device_model_attr = usb_file.getAttribute(
                BlackboardAttribute.Type(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_DEVICE_MODEL))
            device_model = device_model_attr.getValueString() if device_model_attr else ""

            # Filtert virtuelle USB-Geräte heraus (ROOT_HUB und USB Tablet)
            if "ROOT_HUB" in device_model or "USB Tablet" in device_model:
                continue  # Überspringt dieses Gerät

            # Schreibt Header für die USB-Geräteinformationen in die CSV-Datei
            report.write("USB Device Information\n")
            report.write("Device ID, USB Timestamp, Device Make, Device Model, Data Source\n")

            # Schreibt die USB-Geräteinformationen in die CSV-Datei
            report.write(",".join([device_id, timestamp, device_make, device_model, data_source]) + "\n")

            # Schreibt den Header für die Programme aus
            report.write("Program Executions\n")
            report.write("Program Name, Program Timestamp, Count, Comment, Path\n")

            # Vergleicht die Programmausführungszeit mit der USB-Zeit
            # Iteriert durch die Programmausführungsdateien
            for program_file in sorted_program_files:
                program_name = ""
                program_timestamp = ""
                program_count = ""
                program_comment = ""
                program_path = ""

                # Holt den Zeitstempel der Programmausführung und setzt den Zeitstempel
                program_timestamp_attr = program_file.getAttribute(
                    BlackboardAttribute.Type(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_DATETIME))
                program_timestamp_long = program_timestamp_attr.getValueLong() if program_timestamp_attr else ""

                if program_timestamp_long:
                    program_utc_time = Instant.ofEpochSecond(program_timestamp_long)            # Konvertiert den Zeitstempel in UTC
                    program_local_time = ZonedDateTime.ofInstant(program_utc_time, zone_id)     # Wandelt in lokale Zeit um
                    program_timestamp = program_local_time.format(DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss.SSS"))   # Formatiert den Zeitstempel

                # Überprüft, ob die Programmausführung innerhalb von 5 Minuten nach dem USB-Anschluss liegt
                if local_time and abs((program_utc_time.toEpochMilli() - utc_time.toEpochMilli()) / 60000) <= 5:
                    # Holt den Programmnamen
                    program_name_attr = program_file.getAttribute(
                        BlackboardAttribute.Type(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_PROG_NAME))
                    program_name = program_name_attr.getValueString() if program_name_attr else ""
                    # Nur verdächtige Programme aufnehmen
                    if any(exe in program_name.lower() for exe in suspected_executables):
                        # Holt die Ausführungsanzahl
                        program_count_attr = program_file.getAttribute(
                            BlackboardAttribute.Type(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_COUNT))
                        program_count = program_count_attr.getValueInt() if program_count_attr else ""
                        # Holt den Kommentar
                        program_comment_attr = program_file.getAttribute(
                            BlackboardAttribute.Type(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_COMMENT))
                        program_comment = program_comment_attr.getValueString() if program_comment_attr else ""
                        # Holt den Pfad des Programms
                        program_path_attr = program_file.getAttribute(
                            BlackboardAttribute.Type(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_PATH))
                        program_path = program_path_attr.getValueString() if program_path_attr else ""
                        # Schreibt die Programmausführungsdaten in die CSV-Datei
                        report.write(",".join([program_name, program_timestamp, str(program_count), program_comment, program_path]) + "\n")

            # Erhöht den Fortschritt der Fortschrittsanzeige für die Ausführung
            progressBar.increment()

        # Durchsucht die Programmausführungs-Artefakte nach verdächtigen Programmen
        sus_programs_found = False
        for program_file in sorted_program_files:
            # Holt den Programmnamen des Programms aus den Artefakten
            program_name_attr = program_file.getAttribute(
                BlackboardAttribute.Type(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_PROG_NAME))

            if program_name_attr:
                sus_programs_found = True
                break  # Wenn ein verdächtiges Programm gefunden wurde, keine weiteren Programme durchsuchen

        # Wenn ein verdächtiges Programm gefunden wurde, werden die Windows Event Logs Application.evtx und Security.evtx extrahiert
        if sus_programs_found:
            blackboard = Case.getCurrentCase().getSleuthkitCase().getBlackboard()    # Holt das Blackboard der aktuellen Fallinstanz
            dataSources = Case.getCurrentCase().getDataSources()                    # Holt die Datenquellen des Falls
            fileManager = Case.getCurrentCase().getServices().getFileManager()      # Holt den Dateimanager

            # Durchsucht jede Datenquelle nach spezifischen Windows Event Logs (Anwendungs- und Sicherheitslogs)
            for dataSource in dataSources:
                files = fileManager.findFiles(dataSource, "Application.evtx",
                                              "/Windows/System32/winevt/Logs")
                files2 = fileManager.findFiles(dataSource, "Security.evtx",
                                              "/Windows/System32/winevt/Logs")
            # Verarbeitet alle gefundenen Logdateien (Anwendungs- und Sicherheitslogs)
            for file in files + files2:
                # Erstellt ein Artefakt für die Event Logs und markiert es als interessant
                attrs = Arrays.asList(BlackboardAttribute(BlackboardAttribute.Type.TSK_SET_NAME,
                                                          CSVReportModule.moduleName,
                                                          "BadUSB: Event Logs und Datei-Analyse"))
                art = file.newAnalysisResult(BlackboardArtifact.Type.TSK_INTERESTING_FILE_HIT,
                                             Score.SCORE_LIKELY_NOTABLE,
                                             None, "Application und Security Logs gefunden", None, attrs).getAnalysisResult()

                try:
                    # Postet das Artefakt auf das Blackboard
                    blackboard.postArtifact(art, CSVReportModule.moduleName, None)
                except Blackboard.BlackboardException as e:
                    # Fehlerbehandlung beim Posten des Artefakts
                    self.log(Level.SEVERE, "Error indexing artifact " + art.getDisplayName())

        # Wenn Powershell in Programmausführungen gefunden wurde, wird das entsprechende Artefakt für PowerShell.evtx erstellt
        powershell_found = False
        # Durchsucht alle Programme in Programmausführungen nach Powershell
        for program_file in sorted_program_files:
            program_name = ""
            # Holt den Programmnamen
            program_name_attr = program_file.getAttribute(
                BlackboardAttribute.Type(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_PROG_NAME))
            program_name = program_name_attr.getValueString() if program_name_attr else ""

            # Überprüft, ob der Programname "powershell" enthält
            if "powershell" in program_name.lower():
                powershell_found = True     # Markiert Powershell als gefunden
                break   # Keine weiteren Programme durchsuchen, wenn Powershell gefunden wurde

        # Wenn Powershell gefunden wurde, dann werden die PowerShell Event Logs extrahiert
        if powershell_found:
            blackboard = Case.getCurrentCase().getSleuthkitCase().getBlackboard()
            dataSources = Case.getCurrentCase().getDataSources()
            fileManager = Case.getCurrentCase().getServices().getFileManager()

            # Durchsucht die Datenquellen nach dem PowerShell Event Log
            for dataSource in dataSources:
                files = fileManager.findFiles(dataSource, "Windows PowerShell.evtx",
                                              "/Windows/System32/winevt/Logs")

            # Verarbeitet alle gefundenen PowerShell Event Logdateien
            for file in files:
                # Erstellt ein Artefakt für das PowerShell Event Log und markiert es als interessant
                attrs = Arrays.asList(BlackboardAttribute(BlackboardAttribute.Type.TSK_SET_NAME,
                                                          CSVReportModule.moduleName,
                                                          "BadUSB: Event Logs und Datei-Analyse"))
                art = file.newAnalysisResult(BlackboardArtifact.Type.TSK_INTERESTING_FILE_HIT,
                                             Score.SCORE_LIKELY_NOTABLE,
                                             None, "Windows PowerShell Log gefunden", None, attrs).getAnalysisResult()

                try:
                    # Postet das PowerShell Artefakt auf das Blackboard
                    blackboard.postArtifact(art, CSVReportModule.moduleName, None)
                except Blackboard.BlackboardException as e:
                    # Fehlerbehandlung beim Posten des Artefakts
                    self.log(Level.SEVERE, "Error indexing artifact " + art.getDisplayName())

            # Liste der relevanten PowerShell-Befehle
            defender_commands = [
                "Set-MpPreference -DisableRealtimeMonitoring",
                "Set-MpPreference -DisableBehaviorMonitoring",
                "Set-MpPreference -DisableBlockAtFirstSeen",
            ]

            # Überprüft die PowerShell-Befehle auf Hinweise zum Deaktivieren von Windows Defender
            powershell_defender_disabled = False
            powershell_files = fileManager.findFiles(dataSource, "ConsoleHost_history.txt",
                                                     "/Users/%/AppData/Roaming/Microsoft/Windows/PowerShell/PSReadLine")

            suspicious_ps_file = None  # Variable, um die Datei zu speichern, die den verdächtigen Befehl enthält

            for ps_file in powershell_files:
                # Holen des Raw-Dateiinhalts
                rawFile = ReadContentInputStream(ps_file)
                fileBuffer = jarray.zeros(ps_file.getSize(), "b")  # Erstelle ein Byte-Array entsprechend der Dateigröße
                filebytes = rawFile.read(fileBuffer)  # Lese die Datei in das Byte-Array

                # Entferne die ersten 2 ungültigen Werte (-1, -2) aus dem Byte-Array
                byte_array = fileBuffer[2:]

                # Umwandlung der Bytes in einen lesbaren String
                content = ""
                for byte in byte_array:
                    content += chr(byte)

                # Ersetze Null-Bytes (wenn vorhanden)
                content = content.replace('\x00', '')
                for command in defender_commands:
                    if command in content:
                        powershell_defender_disabled = True
                        suspicious_ps_file = ps_file
                        break
                if powershell_defender_disabled:
                    break

            # Poste die PowerShell-Befehlshistorie-Datei auf das Blackboard
            if ps_file:
                attrs = Arrays.asList(BlackboardAttribute(BlackboardAttribute.Type.TSK_SET_NAME,
                                                          CSVReportModule.moduleName,
                                                          "BadUSB: Event Logs und Datei-Analyse"))
                art = ps_file.newAnalysisResult(BlackboardArtifact.Type.TSK_INTERESTING_FILE_HIT,
                                                           Score.SCORE_LIKELY_NOTABLE,
                                                           None,
                                                           "PowerShell Befehlshistorie gefunden",
                                                           None, attrs).getAnalysisResult()
                try:
                    blackboard.postArtifact(art, CSVReportModule.moduleName, None)
                except Blackboard.BlackboardException as e:
                    self.log(Level.SEVERE, "Error indexing artifact " + art.getDisplayName())

            # Wenn ein Hinweis auf das Deaktivieren von Windows Defender in der PowerShell Befehlshistorie gefunden wurde
            if powershell_defender_disabled:
                blackboard = Case.getCurrentCase().getSleuthkitCase().getBlackboard()
                dataSources = Case.getCurrentCase().getDataSources()
                fileManager = Case.getCurrentCase().getServices().getFileManager()

                # Suche nach Windows Defender Event Logs
                for dataSource in dataSources:
                    files = fileManager.findFiles(dataSource, "Microsoft-Windows-Windows Defender%4Operational.evtx",
                                                  "/Windows/System32/winevt/Logs")

                for file in files:
                    # Erstellt ein Artefakt für das Defender Event Log
                    attrs = Arrays.asList(BlackboardAttribute(BlackboardAttribute.Type.TSK_SET_NAME,
                                                              CSVReportModule.moduleName,
                                                              "BadUSB: Event Logs und Datei-Analyse"))
                    art = file.newAnalysisResult(BlackboardArtifact.Type.TSK_INTERESTING_FILE_HIT,
                                                 Score.SCORE_LIKELY_NOTABLE,
                                                 None, "Windows Defender Log gefunden", None, attrs).getAnalysisResult()
                    try:
                        blackboard.postArtifact(art, CSVReportModule.moduleName, None)
                    except Blackboard.BlackboardException as e:
                        self.log(Level.SEVERE, "Error indexing artifact " + art.getDisplayName())

        report.close()      # Schließt den Bericht und die Datei

        # Fügt den Bericht zum Fall hinzu, damit er im Baum angezeigt wird
        Case.getCurrentCase().addReport(fileName, self.moduleName, "BadUSB Activity Investigation Report")
        # Setzt den Fortschritt auf abgeschlossen
        progressBar.complete(ReportStatus.COMPLETE)
