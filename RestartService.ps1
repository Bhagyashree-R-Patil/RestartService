<#
SCRIPT NAME            : RestartService.ps1
IN REPOSITORY          : No
AUTHOR & EMAIL         : Bhagyashree R Patil: bhagyashree.r-patil@capgemini.com
COMPANY                : Capgemini
TAGS                   : Remediation
STATUS                 : Partially Tested
DATE OF CHANGES        : Dec 22nd, 2025  
VERSION                : 1.0
RELEASENOTES           : Initial version - Script to restart a specified Windows service, handling both running and stopped states, with logging and error handling.
APPROVED               : No
SUPPORT                : Document provided with script logic.
DEX TOOLS              : NA
DEPENDENCIES           : Prerequisite: Run the script with administrative privileges.
CONTEXT                : System
OS                     : Windows
SYNOPSIS               : Script to restart a specified Windows service, handling both running and stopped states, with logging and error handling.
DESCRIPTION            : This PowerShell script is designed to restart a specified Windows service. It checks the current status of the service and performs the appropriate action:
                            - If the service is running, it attempts to restart it using the Restart-Service cmdlet.
                            - If the service is stopped, it starts it using the Start-Service cmdlet.
                            - If the service is in a transitional state, it attempts a controlled restart (stop then start).
                         The script includes logging functionality to record actions taken and any errors encountered during execution. It also checks for administrative privileges before attempting to manage the service.             
INPUTS                 : Service name passed as an argument when executing the script.
OUTPUTS                : Log messages indicating:
                            - The target service name.
                            - The current status of the service.
                            - Actions taken (stopping, starting, restarting).
                            - Success or error messages related to service management.
VARIABLE DESCRIPTION   : $MyInvocation = It contains information about how script, function, or command was invoked. For creating log file name
                         $ScriptName = Stores the full path of the script file (from $MyInvocation.ScriptName).
                         $ScriptPath = Stores only the folder(directory)path where the script is located.
                         $ScriptNameOnly = Stores just the scriptr file name.
                         $Logfile = Path to the log file where script activity messages will be written.
                         $LogMessage = A formatted log string with timestamp and message, used to record actions into the log file.
                         $ServiceName = The name of the Windows service to be restarted, passed as an argument to the script.
                         $TimeoutSeconds = The maximum time (in seconds) to wait for the service to reach the desired status during start/stop operations.
                         $svc = The ServiceController object representing the target Windows service, used to check its status and perform start/stop operations.
                         $DesiredStatus = The target status ('Running' or 'Stopped') that the script waits for the service to reach during operations.
                         $deadline = The calculated time limit for waiting operations, based on the current time plus the specified timeout duration.
                         $LogString = The message string passed to the WriteLog function for logging.       
                         $Stamp = The current date and time formatted for log entries.
                         $LogMessage = The complete log entry string combining the timestamp and the log message.                      
NOTES                  : - Ensure to run the script with administrative privileges to manage Windows services.
                         - The script assumes that the service name is provided as an argument when executing the script.
                         - Logging is done in a text file located in the same directory as the script.
LOGIC DOCUMENT         : Yes          
#>

# ==================== Logging setup (as provided) ====================
###### Used to create log file name, same as script name under same folder path as script folder path #######
$ScriptName = & { $myInvocation.ScriptName }
$ScriptPath = Split-Path -parent $ScriptName
$ScriptName = Split-Path $ScriptName -Leaf
$ScriptNameOnly = $ScriptName -replace '.PS1',''
$LogFile = "$ScriptPath\$ScriptNameOnly" + "Log.txt"

########## Function: Write messages to log file ########
function Write-Log {
    Param ([string]$LogString)
    $Stamp = (Get-Date).toString("yyyy/MM/dd HH:mm:ss")
    $LogMessage = "$Stamp $LogString"
    try {
        Add-content $LogFile -value $LogMessage
    }
    catch {
        Write-Warning "Failed to write to log file: $($_.Exception.Message)"
    }
}

############# Script started message to console & log file #############
Write-Output "==================== SCRIPT EXECUTION STARTED ===================="
Write-Log    "==================== SCRIPT EXECUTION STARTED ===================="

# ==================== Capture service name from first argument ====================
if (-not $args -or [string]::IsNullOrWhiteSpace($args[0])) {
    Write-Log    "ERROR: No service name provided as argument. Please provide the Windows service name to restart."
    Write-Output "ERROR: No service name provided as argument. Please provide the Windows service name to restart."
    exit 1
} else {
    $ServiceName = $args[0].Trim()
    Write-Log    "INFO: Service name received from args: '$ServiceName'"
    Write-Output "INFO: Service name received from args: '$ServiceName'"
}

# ==================== Settings ====================
$TimeoutSeconds = 60  # Max time to wait for state transitions
$MaxRetries = 3       # Max retry attempts for timeouts

# ==================== Admin privilege check ====================
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()
    ).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Log    "ERROR: This script must be run as Administrator to manage Windows services."
    Write-Output "ERROR: This script must be run as Administrator to manage Windows services."
    exit 1
}

# ==================== Helper Functions ====================

function Get-ServiceDisplayName {
    param([string]$ServiceName)
    try {
        $allServices = Get-Service
        $byDisplayName = $allServices | Where-Object { $_.DisplayName -eq $ServiceName }
        if ($byDisplayName) {
            return $byDisplayName.Name
        }
        return $null
    }
    catch {
        Write-Log "WARN: Error searching for service by display name: $($_.Exception.Message)"
        return $null
    }
}

# ==================== Service Discovery and Validation ====================
# First try direct service name, then try by display name
try {
    $svc = Get-Service -Name $ServiceName -ErrorAction Stop
    Write-Log    "INFO: Service found by name: '$ServiceName'"
    Write-Output "INFO: Service found by name: '$ServiceName'"
} catch {
    Write-Log    "WARN: Service '$ServiceName' not found by name. Attempting to find by display name..."
    Write-Output "WARN: Service '$ServiceName' not found by name. Attempting to find by display name..."
    
    try {
        $actualServiceName = Get-ServiceDisplayName -ServiceName $ServiceName
        if ($actualServiceName) {
            try {
                $svc = Get-Service -Name $actualServiceName -ErrorAction Stop
                Write-Log    "INFO: Service found by display name. Actual service name: '$actualServiceName'"
                Write-Output "INFO: Service found by display name. Actual service name: '$actualServiceName'"
                $ServiceName = $actualServiceName  # Use the actual service name going forward
            } catch {
                Write-Log    "ERROR: Service '$ServiceName' not found by name or display name."
                Write-Output "ERROR: Service '$ServiceName' not found by name or display name."
                Write-Output "HINT: Use 'Get-Service' to list all services and their exact names."
                exit 1
            }
        } else {
            Write-Log    "ERROR: Service '$ServiceName' not found by name or display name."
            Write-Output "ERROR: Service '$ServiceName' not found by name or display name."
            Write-Output "HINT: Use 'Get-Service' to list all services and their exact names."
            exit 1
        }
    }
    catch {
        Write-Log    "ERROR: Failed to search for service by display name: $($_.Exception.Message)"
        Write-Output "ERROR: Failed to search for service by display name: $($_.Exception.Message)"
        exit 1
    }
}

# Get detailed service information
try {
    $serviceWmi = Get-WmiObject -Class Win32_Service -Filter "Name='$ServiceName'"
    $startType = $serviceWmi.StartMode
    
    Write-Log    "INFO: Service Details - Name: '$ServiceName', DisplayName: '$($svc.DisplayName)', Status: '$($svc.Status)', StartType: '$startType'"
    Write-Output "INFO: Service Details - Name: '$ServiceName', DisplayName: '$($svc.DisplayName)', Status: '$($svc.Status)', StartType: '$startType'"
    
    # Check if service is disabled and exit
    if ($startType -eq "Disabled") {
        Write-Log    "INFO: Service '$ServiceName' is disabled. Exiting script."
        Write-Output "INFO: Service '$ServiceName' is disabled. Exiting script."
        exit 0
    }
    
} catch {
    Write-Log    "WARN: Could not retrieve detailed service information: $($_.Exception.Message)"
    Write-Output "WARN: Could not retrieve detailed service information: $($_.Exception.Message)"
    $startType = "Unknown"
}

# ==================== Helper: wait for service status with retry ====================
function Wait-ForServiceStatus {
    param(
        [System.ServiceProcess.ServiceController]$Service,
        [ValidateSet('Running','Stopped')] [string]$DesiredStatus,
        [int]$TimeoutSeconds = 60,
        [int]$MaxRetries = 3
    )
    
    try {
        for ($retry = 1; $retry -le $MaxRetries; $retry++) {
            Write-Log    "INFO: Waiting for service to reach '$DesiredStatus' state (Attempt $retry of $MaxRetries, Timeout: ${TimeoutSeconds}s)"
            Write-Output "INFO: Waiting for service to reach '$DesiredStatus' state (Attempt $retry of $MaxRetries, Timeout: ${TimeoutSeconds}s)"
            
            $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
            while ((Get-Date) -lt $deadline) {
                try {
                    $Service.Refresh()
                    if ($Service.Status.ToString() -eq $DesiredStatus) { 
                        Write-Log    "SUCCESS: Service reached '$DesiredStatus' state on attempt $retry"
                        Write-Output "SUCCESS: Service reached '$DesiredStatus' state on attempt $retry"
                        return $true 
                    }
                    Start-Sleep -Seconds 2
                }
                catch {
                    Write-Log    "WARN: Error refreshing service status: $($_.Exception.Message)"
                    Start-Sleep -Seconds 2
                }
            }
            
            if ($retry -lt $MaxRetries) {
                Write-Log    "WARN: Timeout on attempt $retry. Retrying..."
                Write-Output "WARN: Timeout on attempt $retry. Retrying..."
                Start-Sleep -Seconds 5  # Brief pause before retry
            }
        }
        
        Write-Log    "ERROR: Failed to reach '$DesiredStatus' state after $MaxRetries attempts"
        Write-Output "ERROR: Failed to reach '$DesiredStatus' state after $MaxRetries attempts"
        return $false
    }
    catch {
        Write-Log    "ERROR: Exception in Wait-ForServiceStatus: $($_.Exception.Message)"
        Write-Output "ERROR: Exception in Wait-ForServiceStatus: $($_.Exception.Message)"
        return $false
    }
}

# Helper for fallback controlled restart (Stop -> Start with waits)
function Invoke-ControlledRestart {
    param([string]$Name, [System.ServiceProcess.ServiceController]$Controller)

    try {
        Write-Log    "INFO: Fallback - Stopping service '$Name' with -Force..."
        Write-Output "INFO: Fallback - Stopping service '$Name' with -Force..."
        Stop-Service -Name $Name -Force -ErrorAction Stop
    } catch {
        Write-Log    "ERROR: Fallback stop failed: $($_.Exception.Message)"
        Write-Output "ERROR: Fallback stop failed: $($_.Exception.Message)"
        throw
    }

    try {
        if (-not (Wait-ForServiceStatus -Service $Controller -DesiredStatus 'Stopped' -TimeoutSeconds $TimeoutSeconds -MaxRetries $MaxRetries)) {
            Write-Log    "ERROR: Timeout waiting for service to reach 'Stopped' during fallback."
            Write-Output "ERROR: Timeout waiting for service to reach 'Stopped' during fallback."
            throw "Timeout waiting for Stopped"
        }
    }
    catch {
        Write-Log    "ERROR: Error waiting for service to stop: $($_.Exception.Message)"
        Write-Output "ERROR: Error waiting for service to stop: $($_.Exception.Message)"
        throw
    }

    try {
        Write-Log    "INFO: Fallback - Starting service '$Name'..."
        Write-Output "INFO: Fallback - Starting service '$Name'..."
        Start-Service -Name $Name -ErrorAction Stop
    } catch {
        Write-Log    "ERROR: Fallback start failed: $($_.Exception.Message)"
        Write-Output "ERROR: Fallback start failed: $($_.Exception.Message)"
        throw
    }

    try {
        if (-not (Wait-ForServiceStatus -Service $Controller -DesiredStatus 'Running' -TimeoutSeconds $TimeoutSeconds -MaxRetries $MaxRetries)) {
            Write-Log    "ERROR: Timeout waiting for service to reach 'Running' during fallback."
            Write-Output "ERROR: Timeout waiting for service to reach 'Running' during fallback."
            throw "Timeout waiting for Running"
        }
    }
    catch {
        Write-Log    "ERROR: Error waiting for service to start: $($_.Exception.Message)"
        Write-Output "ERROR: Error waiting for service to start: $($_.Exception.Message)"
        throw
    }
}

# ==================== Handle based on current service status ====================
try {
    switch ($svc.Status) {
        'Running' {
            # Preferred path: Restart-Service
            try {
                Write-Log    "INFO: Service is Running. Attempting Restart-Service -Force..."
                Write-Output "INFO: Service is Running. Attempting Restart-Service -Force..."
                Restart-Service -Name $ServiceName -Force -ErrorAction Stop
            } catch {
                Write-Log    "WARN: Restart-Service failed: $($_.Exception.Message)"
                Write-Output "WARN: Restart-Service failed: $($_.Exception.Message)"
                # Fallback to controlled restart
                try {
                    Invoke-ControlledRestart -Name $ServiceName -Controller $svc
                } catch {
                    Write-Log    "ERROR: Controlled restart failed after Restart-Service failure: $($_.Exception.Message)"
                    Write-Output "ERROR: Controlled restart failed after Restart-Service failure: $($_.Exception.Message)"
                    exit 1
                }
            }

            # Wait for final Running state after Restart-Service (or after fallback)
            try {
                if (-not (Wait-ForServiceStatus -Service $svc -DesiredStatus 'Running' -TimeoutSeconds $TimeoutSeconds -MaxRetries $MaxRetries)) {
                    Write-Log    "ERROR: Timeout waiting for service to be 'Running' after restart."
                    Write-Output "ERROR: Timeout waiting for service to be 'Running' after restart."
                    exit 1
                }
            }
            catch {
                Write-Log    "ERROR: Error waiting for service to restart: $($_.Exception.Message)"
                Write-Output "ERROR: Error waiting for service to restart: $($_.Exception.Message)"
                exit 1
            }

            Write-Log    "SUCCESS: Service '$ServiceName' restarted and is Running."
            Write-Output "SUCCESS: Service '$ServiceName' restarted and is Running."
        }

        'Stopped' {
            # If stopped, just Start-Service
            Write-Log    "INFO: Service is Stopped. Starting..."
            Write-Output "INFO: Service is Stopped. Starting..."
            try {
                Start-Service -Name $ServiceName -ErrorAction Stop
            } catch {
                Write-Log    "ERROR: Failed to start service: $($_.Exception.Message)"
                Write-Output "ERROR: Failed to start service: $($_.Exception.Message)"
                exit 1
            }

            try {
                if (-not (Wait-ForServiceStatus -Service $svc -DesiredStatus 'Running' -TimeoutSeconds $TimeoutSeconds -MaxRetries $MaxRetries)) {
                    Write-Log    "ERROR: Timeout waiting for service to reach 'Running'."
                    Write-Output "ERROR: Timeout waiting for service to reach 'Running'."
                    exit 1
                }
            }
            catch {
                Write-Log    "ERROR: Error waiting for service to start: $($_.Exception.Message)"
                Write-Output "ERROR: Error waiting for service to start: $($_.Exception.Message)"
                exit 1
            }

            Write-Log    "SUCCESS: Service '$ServiceName' started and is Running."
            Write-Output "SUCCESS: Service '$ServiceName' started and is Running."
        }

        default {
            # Transitional states: StartPending, StopPending, PausePending, ContinuePending
            Write-Log    "INFO: Service is in transitional state '$($svc.Status)'. Attempting Restart-Service..."
            Write-Output "INFO: Service is in transitional state '$($svc.Status)'. Attempting Restart-Service..."

            $restartSucceeded = $true
            try {
                Restart-Service -Name $ServiceName -Force -ErrorAction Stop
            } catch {
                $restartSucceeded = $false
                Write-Log    "WARN: Restart-Service failed from transitional state: $($_.Exception.Message)"
                Write-Output "WARN: Restart-Service failed from transitional state: $($_.Exception.Message)"
            }

            if (-not $restartSucceeded) {
                try {
                    Invoke-ControlledRestart -Name $ServiceName -Controller $svc
                } catch {
                    Write-Log    "ERROR: Controlled restart failed from transitional state: $($_.Exception.Message)"
                    Write-Output "ERROR: Controlled restart failed from transitional state: $($_.Exception.Message)"
                    exit 1
                }
            }

            try {
                if (-not (Wait-ForServiceStatus -Service $svc -DesiredStatus 'Running' -TimeoutSeconds $TimeoutSeconds -MaxRetries $MaxRetries)) {
                    Write-Log    "ERROR: Timeout waiting for service to be 'Running' after transitional restart."
                    Write-Output "ERROR: Timeout waiting for service to be 'Running' after transitional restart."
                    exit 1
                }
            }
            catch {
                Write-Log    "ERROR: Error waiting for service after transitional restart: $($_.Exception.Message)"
                Write-Output "ERROR: Error waiting for service after transitional restart: $($_.Exception.Message)"
                exit 1
            }

            Write-Log    "SUCCESS: Service '$ServiceName' restarted from transitional state and is Running."
            Write-Output "SUCCESS: Service '$ServiceName' restarted from transitional state and is Running."
        }
    }
}
catch {
    Write-Log    "ERROR: Unexpected error during service operation: $($_.Exception.Message)"
    Write-Output "ERROR: Unexpected error during service operation: $($_.Exception.Message)"
    exit 1
}

try {
    Write-Output "==================== SCRIPT EXECUTION COMPLETED ===================="
    Write-Log    "==================== SCRIPT EXECUTION COMPLETED ===================="
    exit 0
}
catch {
    Write-Log    "ERROR: Error during script completion: $($_.Exception.Message)"
    Write-Output "ERROR: Error during script completion: $($_.Exception.Message)"
    exit 1
}
