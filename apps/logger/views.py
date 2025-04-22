from django.shortcuts import render
from .models import Log

# Create your views here.
def createLog(event_code, event_type, event_group, user_level, privledged, action, outcome, additional_data, user_id):
    Log.objects.create(event_code=event_code, event_type=event_type, event_group=event_group, user_level=user_level, privledged=privledged, action=action, outcome=outcome, additional_data=additional_data, user_id=user_id)
    
    # EventCode=1001 EventType="User Management" EventGroup="User Creation Event" UserLevel="Superuser" Privledged="TRUE" Action="Local User Creation Success" Outcome="Success" AdditionalData="User Principal Name" UserID="<user_id>" EventTime="YYYY-MM-DDTHH:MM:SSZ"
    with open(r'tierzerocode.log', 'a') as f:
        f.write(f"EventCode={event_code} EventType={event_type} EventGroup={event_group} UserLevel={user_level} Privledged={privledged} Action={action} Outcome={outcome} AdditionalData={additional_data} UserID={user_id} EventTime=YYYY-MM-DDTHH:MM:SSZ\n")
        f.close()
        
    print(f"EventCode={event_code} EventType={event_type} EventGroup={event_group} UserLevel={user_level} Privledged={privledged} Action={action} Outcome={outcome} AdditionalData={additional_data} UserID={user_id} EventTime=YYYY-MM-DDTHH:MM:SSZ")
    
    return None
    