<?xml version="1.0"?>
<xs:schema targetNamespace="urn:ddb:expandingpulley"
           xmlns='urn:ddb:expandingpulley'           
           xmlns:xs="http://www.w3.org/2001/XMLSchema" >

 <xs:include schemaLocation="commonDefs.xs" />

 <xs:element name="Data">
  <xs:complexType>
   <xs:sequence>
    <xs:element ref="Instance"  />
    <xs:element ref="Command"/>
    <xs:element ref="Autoload" minOccurs="0" maxOccurs="unbounded" />
    <xs:choice minOccurs="0" maxOccurs="unbounded">
     <xs:element ref="PortMap" />
     <xs:element ref="Error" />
    </xs:choice>
    <xs:choice>
     <xs:element ref="Success" />
     <xs:element ref="Failure" />
    </xs:choice> 
   </xs:sequence>
  </xs:complexType>
 </xs:element>

 <xs:element name="PortMap">
    <xs:complexType>
	<xs:sequence>
	  <xs:element ref='Process' minOccurs='0' maxOccurs='unbounded'/>
	</xs:sequence>
	<xs:attribute name='lptimestamp' type='xs:dateTime' use='required'/>
    </xs:complexType>
 </xs:element>

 <xs:element name='Process'>
    <xs:complexType>
	<xs:sequence>
	  <xs:element ref='Port' minOccurs='0' maxOccurs='unbounded'/>
	</xs:sequence>

	<xs:attribute name='name' type='xs:string' use='required'/>
	<xs:attribute name='id' type='xs:nonNegativeInteger' use='required'/>
    </xs:complexType>
 </xs:element>

 <xs:element name='Port'>
    <xs:complexType>
	<xs:simpleContent>
	  <xs:extension base='feEmptyElement'>
	    <xs:attribute name='sourcePort' type='xs:nonNegativeInteger' use='required'/>
	    <xs:attribute name='sourceAddr' type='xs:string' use='required'/>
	    <xs:attribute name='state' type='xs:string' use='required'/>
	    <xs:attribute name='type' type='xs:string' use='required'/>
	  </xs:extension>
	</xs:simpleContent>
    </xs:complexType>
 </xs:element>

</xs:schema>
