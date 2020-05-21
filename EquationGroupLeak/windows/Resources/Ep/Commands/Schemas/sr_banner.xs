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
     <xs:element name="Connected" form="qualified" type="feEmptyElementWithTimestamp" />
     <xs:element ref="Error" />
     <xs:element ref="Transfer" />
    </xs:choice>
    <xs:choice>
     <xs:element ref="Success" />
     <xs:element ref="Failure" />
    </xs:choice> 
   </xs:sequence>
  </xs:complexType>
 </xs:element>

 <xs:element name="Transfer">
  <xs:complexType>
   <xs:choice maxOccurs="unbounded">
    <xs:element name="Data" form="qualified">
     <xs:complexType>
      <xs:simpleContent>
       <xs:extension base="xs:string">
        <xs:attribute name="size"      type="xs:nonNegativeInteger" />
       </xs:extension>
      </xs:simpleContent>
     </xs:complexType>
    </xs:element>
    <xs:element name="Text" form="qualified" type="xs:string"/>
   </xs:choice>
   <xs:attribute name="address" type="xs:string" use="required" />
   <xs:attribute name="port" type="xs:nonNegativeInteger" use="required" />
   <xs:attribute name="lptimestamp" type="xs:dateTime" use="required" />
  </xs:complexType>
 </xs:element>


</xs:schema>
