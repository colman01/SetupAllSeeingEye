//
//  PTXASIS3Request.h
//  pocketTaxi
//
//  Created by Colman Marcus-Quinn on 02.01.12.
//  Copyright (c) 2012 __MyCompanyName__. All rights reserved.
//

#import "ASIS3Request.h"
#import "pocketTaxiAppDelegate.h"
#import <CommonCrypto/CommonHMAC.h>

@interface PTXASIS3Request : ASIS3Request {
    
}


- (NSData *)signedString:(NSString *)secretKey signString:(NSString *)stringToSign;

- (NSString *)stringToSignForHeaders;

- (NSString*)base64:(NSData*)theData;

@end
