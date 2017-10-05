import Mimecast

def main():

    # Login into Mimecast
    # Mimecast Logon Details
    # Need to have a logon in Basic Admin Role
    # Get API keys form Mimecast support for your app
    USER = 'mimecast-api-access@test.com'
    PASS = ''
    APP_ID = ''
    APP_KEY = ''

    mc = Mimecast.Mimecast(USER, PASS, APP_ID, APP_KEY)

    # Get Mimecast alias list
    print("Getting Mimecast Users - test.com...")
    mimecastEmails = set()
    mimecastUsers = mc.getUserList(domain='test.com')
    for user in mimecastUsers:
        #print (user.emailAddress, user.alias, user.addressType)
        mimecastEmails.add(user.emailAddress)

    checkSet = set(['test@test.com'])
    set1 = set({x for x in mimecastEmails if (x not in checkSet)})
    print("\nMimecast not in set: ")
    for x in sorted(set1):
        print(x)

if __name__ == '__main__':
    main()
