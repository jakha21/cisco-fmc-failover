#!/usr/bin/python
import requests
import json
import base64
from time import sleep
from pathlib import Path

# Disable SSL warnings
requests.packages.urllib3.disable_warnings()

####### LOADING NECESSARY DATA FORM OPTIONS FILE ################################
optionFile = Path(__file__).parent / './options.json'
with open(optionFile, "rb") as opt:
    options = json.load(opt)['firepower']
    USERNAME = options['username']
    PASSWORD = options['password']
    FMC = options['address']
    ROUTE = options['failover_route']
    GATEWAY = options['failover_gateway']
    FO_INTERFACE = options['failover_interface']
#################################################################################

#Creating base64 encoded credential string to get authentication token
credentials = USERNAME + ":" + PASSWORD
sample_string_bytes = credentials.encode("ascii")
base64_bytes = base64.b64encode(sample_string_bytes)
encoded_credentials = base64_bytes.decode("ascii")

#Header info to retrieve token
headers = {"Authorization" : "Basic " + encoded_credentials}

#Common variables for target device
domainUUID = 'e276abec-e0f2-11e3-8169-6d9ed49b625f'
containerUUID = 'e4d6cf40-8dea-11ec-ba49-f72fea9d1bf4'
baseurl = f'https://{FMC}/api/fmc_config/v1/domain/{domainUUID}'


class FirePower():

    def __init__(self):
        # Set up HTTP session & get auth token 
        with requests.Session() as self.s:
            self.token = self.authRequest()

    def authRequest(self):
        # Authenticate to FMC and retrieve access token
        authurl = f'https://{FMC}/api/fmc_platform/v1/auth/generatetoken'
        print('\n *** RETRIEVING AUTHENTICATION TOKEN *** \n')
        resp = self.s.post(authurl, headers=headers, verify=False)
        if resp.status_code == 204:
            print("\n ACCESS TOKEN RETRIEVED --> " + resp.headers['X-auth-access-token'])
            return resp.headers['X-auth-access-token']
        else:
            print('FAILED TO RETRIEVE TOKEN, Response code: ' + str(resp.status_code))
            print(resp.headers)

    def addRoute(self):
        # Function to add new route to routing table
        print('Getting current route table...\n')
        # First we check to make sure the route already exists,
        # otherwise no work is necessary
        route = self.doesRouteExist()
        if route:
            # If our backup route already exists, make no changes
            print('DEVICE IS ALREADY IN FAILOVER STATE. \
                  NO CHANGES MADE TO ROUTING TABLE \n')
            return False
        else:
            # If not already failed over - proceed to add backup route
            print('NO BACKUP ROUTE CURRENTLY IN ROUTING TABLE. \
                   ADDING BACKUP ROUTE... \n')
            # First create a route object - a collection of data required
            # to add a static route entry
            route_data = self.createRouteObject()
            add_url = f'/devices​/devicerecords​/{containerUUID}​/routing​​/ipv4staticroutes'
            print('CREATING ROUTE OBJECT... \n')
            # Post to route creation API
            self.postData(add_url, route_data)
            print('\n *** STATIC ROUTE HAS BEEN ADDED SUCCESSFULLY! *** \n')
            if self.deployPolicy() is True:
                print("\n *** ROUTE SUCCESSFULLY ADDED & CHANGES DEPLOYED. *** \n")
                return True
            else:
                print("\n *** ERROR: DEPLOYMENT ERROR. ROUTE MAY NOT BE ADDED. *** \n")
                return False


    def delRoute(self):
        # Function to delete static route from routing table
        print('GETTING CURRENT ROUTE TABLE... \n')
        # First we check to make sure the route already exists,
        # otherwise no work is necessary
        route = self.doesRouteExist()
        if route is False:
            # If no route is found, then no changes are needed
            print('DEVICE IS NOT IN FAILOVER STATE AT THE MOMENT. \
                  NO CHANGES MADE TO ROUTING TABLE \n')
            return False
        else:
            del_url = f'/devices​/devicerecords​/{containerUUID}​/routing​/ipv4staticroutes/' + str(route['id'])
            if self.deleteData(del_url) is True:
                print('\n *** STATIC ROUTE HAS BEEN REMOVED SUCCESSFULLY! *** \n')
                if self.deployPolicy() is True:
                    print(" \n ROUTE SUCCESSFULLY REMOVED & CHANGES DEPLOYED. \n")
                    return True
                else:
                    print(" \n ERROR: DEPLOYMENT ERROR. ROUTE MAY NOT BE REMOVED. \n")
                    return False
        
                
    def deployPolicy(self):
        # Policy deployment & status checking
        deploy_url = '/deployment/deploymentrequests'
        deply_status_url = f'/deployment/deployabledevices/{containerUUID}/deployments'
        print('\n ^^^ LAUNCHING DEPLOYMENT OPERATION ^^^ \n')
        # Send POST request, which starts deployment. Grab ID to check status
        deploy_data = {
        "type": "DeploymentRequest",
        "version": "0",
        "forceDeploy": False,
        "ignoreWarning": True,
        "deviceList": ['e4d6cf40-8dea-11ec-ba49-f72fea9d1bf4'],
        "deploymentNote": "Deployed via API"}

        deploymentID = json.loads(self.postData(deploy_url, deploy_data))['metadata']['task']['id']
        print("Changes being deployed... Deployment ID: " + deploymentID)
        deployed = False

        while deployed is False:
            # Deployment is not instant - we will give it a
            # few seconds between checks
            # NOTE: Can take a long time depending on appliance
            #       resources & number of changes
            sleep(8)
            # Grab current deployment task list
            taskList = json.loads(self.getData(deply_status_url))
            # Search for our deployment task by ID
            print("Current deployment status --> " + taskList['items'][0]['status'])
            for task in taskList['items']:
                # Check the status of our deployment
                if (task['id'])[-11:] == deploymentID and task['status'] == 'SUCCEEDED':
                    print("Final deployment status --> " + task['status'])
                    deployed = True
                    return True
                elif task['id'] == deploymentID and task['status'] != 'SUCCEEDED':
                    # If changes not yet deployed, check again momentarily
                    print("Deployment status is: " + task['status'])
                    deployed = False

    def doesRouteExist(self):
        # Pull current routing table and look for our backup route
        current_routes = self.getRoutes()
        # If no routes exist, skip everything
        if current_routes == []:
            return False
        # Iterate through all routes to find our specific backup route
        for route in current_routes:
            if '/32' in GATEWAY and ROUTE:
                #Fetching gateway ID
                gw_id = self.getGatewayID(route['id'])
                gateway = self.getHostObject(gw_id)
                #Fetching host object ID
                net_id = self.getNetworkID(route['id'])
                dest_network = self.getHostObject(net_id)
                # Match based on route prefix & upstream next hop gateway
                if gateway == GATEWAY.split('/')[0] and dest_network == ROUTE.split('/')[0]:
                    print('FOUND ROUTE TO %s VIA %s' % (dest_network, gateway) , "\n")
                    return route
            if '/32' in GATEWAY:
                #Fetching gateway ID
                gw_id = self.getGatewayID(route['id'])
                gateway = self.getHostObject(gw_id)
                #Fetching host object ID
                net_id = self.getNetworkID(route['id'])
                dest_network = self.getNetworkObject(net_id)
                # Match based on route prefix & upstream next hop gateway
                if gateway == GATEWAY.split('/')[0] and dest_network == ROUTE:
                    print('FOUND ROUTE TO %s VIA %s' % (dest_network, gateway) , "\n")
                    return route
            if '/32' in ROUTE:
                #Fetching gateway ID
                gw_id = self.getGatewayID(route['id'])
                gateway = self.getNetworkObject(gw_id)
                #Fetching host object ID
                net_id = self.getNetworkID(route['id'])
                dest_network = self.getHostObject(net_id)
                # Match based on route prefix & upstream next hop gateway
                if gateway == GATEWAY and dest_network == ROUTE.split('/')[0]:
                    print('FOUND ROUTE TO %s VIA %s' % (dest_network, gateway) , "\n")
                    return route
            else:
                #Fetching gateway ID
                gw_id = self.getGatewayID(route['id'])
                gateway = self.getNetworkObject(gw_id)
                #Fetching host object ID
                net_id = self.getNetworkID(route['id'])
                dest_network = self.getNetworkObject(net_id)
                # Match based on route prefix & upstream next hop gateway
                if gateway == GATEWAY and dest_network == ROUTE:
                    print('FOUND ROUTE TO %s VIA %s' % (dest_network, gateway) , "\n")
                    return route
        return False
    
    def getHostObject(self, id):
        # Get host object IP Address by known ID
        host_url = "/object/hosts/" + str(id)
        netobj = self.getData(host_url)
        try:
            return json.loads(netobj)['value']
        except KeyError:
            print('NO OBJECT FOUND FOR ID -> '+ str(id) + '\n')

    def getNetworkObject(self, id):
        # Get network object IP Address by known ID
        network_url = "/object/networks/" + str(id)
        netobj = self.getData(network_url)
        try:
            return json.loads(netobj)['value']
        except KeyError:
            print('NO OBJECT FOUND FOR ID -> '+ str(id) + '\n')

    def getInterfaceName(self, failover_interface):
        # Get interface name by known ID
        iface_url = f'/devices/devicerecords/{containerUUID}/physicalinterfaces'
        ifaceList = self.getData(iface_url)

        for iface in json.loads(ifaceList)['items']:
            # Iterate through all interfaces to find physical interface id
            intf_url = f'/devices/devicerecords/{containerUUID}/physicalinterfaces/' + iface['id']
            netobj = self.getData(intf_url)
            if json.loads(netobj)['name'] == failover_interface:
                try:
                    return json.loads(netobj)['ifname']
                except KeyError:
                    print('NO NAME FOUND FOR ID -> '+ iface['id'] + '\n')
                    pass

    def getDuplicateObject(self, name, address):
        # Get object ID by known object name
        if address[-2:] == '32':
            host_url = '/object/hosts?filter=nameOrValue:' + name 
        else:
            host_url = '/object/networks?filter=nameOrValue:' + name
        netobj = self.getData(host_url)
        return json.loads(netobj)['items'][0]['id']

    def createGateway(self, address):
        # Send request to createNetworkObject with gateway specific parameters
        host_name = 'FAILOVER_GW_' + str(address.split('/')[0])
        gateway = self.createNetworkObject(host_name, address)
        return gateway, host_name

    def createNetwork(self, address):
        # Send request to createNetworkObject with network specific parameters
        host_name = 'FAILOVER_NET_' + str(address.split('/')[0])
        netobj = self.createNetworkObject(host_name, address)
        return netobj, host_name

    def createRouteObject(self):
        # Collect required data:
        iface_name = self.getInterfaceName(FO_INTERFACE)
        network_ID, network_name = self.createNetwork(ROUTE)
        gateway_ID, gateway_name = self.createGateway(GATEWAY)
        # Generate dictionary of required values to create static route object
        routeobject = {}
        routeobject['interfaceName'] = iface_name
        routeobject['selectedNetworks'] = [{}]
        routeobject['selectedNetworks'][0] = {}
        routeobject['selectedNetworks'][0]['overridable'] = False
        routeobject['selectedNetworks'][0]['name'] = network_name
        routeobject['selectedNetworks'][0]['id'] = network_ID
        routeobject['gateway'] = {'object':{}}
        routeobject['gateway']['object']['overridable'] = False
        routeobject['gateway']['object']['name'] = gateway_name
        routeobject['gateway']['object']['id'] = gateway_ID
        routeobject['metricValue'] = 1
        routeobject['type'] = "IPv4StaticRoute"
        routeobject['isTunneled'] = False
        return routeobject

    def createNetworkObject(self, name, address):
        # Create a new network object
        if address[-2:] == '32':
            host_url = '/object/hosts'
            object_type = 'Host'
            address = address.split('/')[0]
        else:
            host_url ='/object/networks'
            object_type = 'Network'

        # Define host details
        host_data = {}
        host_data['type'] = object_type
        host_data['value'] = address
        host_data['overridable'] = False
        host_data['description'] = "Created by ISP Failover automation"
        host_data['name'] = name

        # Post to object creation API
        print('CREATE: Network Object: ' + address)
        netobj = self.postData(host_url, host_data)

        try:
            # Check to see if we received duplicate object error
            if 'already exists.' in json.loads(netobj)['error']['messages'][0]['description']:
                # If already created... just go find existing object ID
                if '/' not in address:
                    address = address + '/32'
                dupID = self.getDuplicateObject(name, address)
                print('FOUND DUPLICATE ID: ' + dupID)
                return dupID
            elif 'Invalid' in json.loads(netobj)['error']['messages'][0]['description']:
                print("Object declared incorrectly, enter valid data!")
            else:
                # If object created, return object ID
                print('NEW OBJECT ID: ' + json.loads(netobj)['id'])
                return json.loads(netobj)['id']
        except KeyError:
            return json.loads(netobj)['id']

    def getRoutes(self):
        # Grab list of ALL static route entries
        route_url = f'/devices​/devicerecords​/{containerUUID}​/routing​/ipv4staticroutes'
        route_data = self.getData(route_url)
        return json.loads(route_data)['items']
    
    def getGatewayID(self, id):
        # Get gateway info for each static route
        gw_url = f'/devices​/devicerecords​/{containerUUID}​/routing​/ipv4staticroutes/' + str(id)
        gw_data = self.getData(gw_url)
        return json.loads(gw_data)['gateway']['object']['id']
    
    def getNetworkID(self, id):
        # Get destination network info for each static route
        net_url = f'/devices​/devicerecords​/{containerUUID}​/routing​/ipv4staticroutes/' + str(id)
        net_data = self.getData(net_url)
        return json.loads(net_data)['selectedNetworks'][0]['id'].split('/')[0]
        
    def getData(self, url):
        # General function for HTTP GET requests with authentication token
        headers = {'X-auth-access-token': self.token}

        #concat issue fixed by removing ZWSP 
        get_url = baseurl + url.replace('\u200b', '')
        print('Getting data from -> ' + get_url + '\n')
        resp = self.s.get(get_url, headers=headers, verify=False)
        try:
            return resp.text
        except (TypeError, KeyError):
            print('Unable to process REQUEST, Response code: ' + str(resp.status_code))
            pass

    def deleteData(self, url):
        # General function for HTTP DELETE requests
        headers = {'X-auth-access-token': self.token}

        delete_url = baseurl + url.replace('\u200b', '')
        print('Removing data from -> ' + delete_url + '\n')
        resp = self.s.delete(delete_url, headers=headers, verify=False)
        if resp.status_code == 200 or 204:
            return True
        else:
            print('Unable to process REQUEST, Response code: ' + str(resp.status_code))
            return False

    def postData(self, url, payload=None):
        # General function for HTTP POST requests with authentication token
        headers = {'X-auth-access-token': self.token}

        post_url = baseurl + url.replace('\u200b', '')
        print('Adding data to -> ' + post_url + '\n')
        resp = self.s.post(post_url, headers=headers, verify=False,
                           json=payload)
        if resp.status_code == 200 or 201 or 202:
            return resp.text
        if resp.status_code == 422 or 'already exists.' in json.loads(resp.text)['error']['messages'][0]['description']:
            print('OBJECT ALREADY EXISTS')
            return resp.text
        else:
            print('Unable to process REQUEST, Response code: ' + str(resp.status_code))
            print(resp.text)

if __name__ == "__main__":
    FirePower()
