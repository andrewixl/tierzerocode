from django.shortcuts import render
from .models import Log
import os
import platform

def createLog(session_id, event_code, event_type, event_group, user_level, privileged, action, outcome, additional_data, user_id, ip_address, user_agent, browser, operating_system):
    Log.objects.create(session_id=session_id, event_code=event_code, event_type=event_type, event_group=event_group, user_level=user_level, privileged=privileged, action=action, outcome=outcome, additional_data=additional_data, user_id=user_id, ip_address=ip_address, user_agent=user_agent, browser=browser, operating_system=operating_system)
    # Determine log file path based on OS
    if platform.system() == 'Linux':
        log_path = os.path.join('/db', 'tierzerocode.log')
    else:
        log_path = 'tierzerocode.log'
    with open(log_path, 'a') as f:
        f.write(f"SessionID={session_id} EventCode={event_code} EventType={event_type} EventGroup={event_group} UserLevel={user_level} Privileged={privileged} Action={action} Outcome={outcome} AdditionalData={additional_data} UserID={user_id} IPAddress={ip_address} UserAgent={user_agent} Browser={browser} OperatingSystem={operating_system} EventTime=YYYY-MM-DDTHH:MM:SSZ\n")
    print(f"SessionID={session_id} EventCode={event_code} EventType={event_type} EventGroup={event_group} UserLevel={user_level} Privileged={privileged} Action={action} Outcome={outcome} AdditionalData={additional_data} UserID={user_id} IPAddress={ip_address} UserAgent={user_agent} Browser={browser} OperatingSystem={operating_system} EventTime=YYYY-MM-DDTHH:MM:SSZ")
    return None
    