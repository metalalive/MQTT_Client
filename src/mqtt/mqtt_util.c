#include "mqtt_include.h"



mqttProp_t*  mqttGetPropByType( mqttProp_t* head, mqttPropertyType type )
{
    if(type == MQTT_PROP_NONE) { return NULL; }
    mqttProp_t *curr_node = NULL;

    for(curr_node = head; curr_node != NULL; curr_node = curr_node->next ) 
    {
        if(curr_node->type == type) { break; }
    } // end of for-loop
    return curr_node;
} // end of mqttGetPropByType




