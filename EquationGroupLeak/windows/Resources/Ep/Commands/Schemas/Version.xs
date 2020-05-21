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
     <xs:element ref="Error" />
     <xs:element ref="ListeningPost"/>
     <xs:element name="Implant"  type="feVersionData" form="qualified"/>
    </xs:choice>
    <xs:choice>
     <xs:element ref="Success" />
     <xs:element ref="Failure" />
    </xs:choice> 
   </xs:sequence>
  </xs:complexType>
 </xs:element>

  <xs:element name="ListeningPost">
    <xs:complexType>
	<xs:sequence>
	    <xs:element name="Compiled" type="feVersionData" form="qualified"/>
	    <xs:element name="Base"  type="feVersionData" form="qualified"/>
	    <xs:element name="Plugins" type="feVersionData" form="qualified"/>
	</xs:sequence>
	<xs:attribute name="lptimestamp" type="xs:dateTime"/>
    </xs:complexType>
  </xs:element>
  <xs:complexType name="feVersionData">
   <xs:simpleContent>
    <xs:extension base="xs:string">
     <xs:attribute name="lptimestamp" type="xs:dateTime" />
     <xs:attribute name="build"       type="xs:nonNegativeInteger" />
     <xs:attribute name="minor"       type="xs:nonNegativeInteger" />
     <xs:attribute name="major"       type="xs:nonNegativeInteger" />
    </xs:extension>
   </xs:simpleContent>
  </xs:complexType>
 

</xs:schema>

