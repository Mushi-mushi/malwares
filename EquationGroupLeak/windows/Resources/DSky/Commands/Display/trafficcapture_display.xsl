<?xml version='1.1' ?>
<xsl:transform xmlns:xsl="http://www.w3.org/1999/XSL/Transform" version="1.0">

	<xsl:import href="include/StandardTransforms.xsl"/>
  
	<xsl:template match="Status">
		<xsl:text>          Version : </xsl:text>
		<xsl:value-of select="Version/@major"/>
		<xsl:text>.</xsl:text>
		<xsl:value-of select="Version/@minor"/>
		<xsl:text>.</xsl:text>
		<xsl:value-of select="Version/@revision"/>
		<xsl:call-template name="PrintReturn"/>
		
		<xsl:text>  Packet Scanning : </xsl:text>
		<xsl:choose>
			<xsl:when test="@filterActive = 'true'">
				<xsl:text>ENABLED</xsl:text>
			</xsl:when>
			<xsl:otherwise>
				<xsl:text>DISABLED</xsl:text>
			</xsl:otherwise>
		</xsl:choose>
		<xsl:call-template name="PrintReturn"/>
		
		<xsl:text>   Thread Running : </xsl:text>
		<xsl:choose>
			<xsl:when test="@threadRunning = 'true'">
				<xsl:text>YES</xsl:text>
			</xsl:when>
			<xsl:otherwise>
				<xsl:text>NO</xsl:text>
			</xsl:otherwise>
		</xsl:choose>
		<xsl:call-template name="PrintReturn"/>
		
		<xsl:text>    Max File Size : </xsl:text>
		<xsl:choose>
			<xsl:when test="@maxCaptureSize = 0">
				<xsl:text>Unlimited</xsl:text>
			</xsl:when>
			<xsl:otherwise>
				<xsl:value-of select="@maxCaptureSize"/>
			</xsl:otherwise>
		</xsl:choose>
		<xsl:call-template name="PrintReturn"/>
		
		<xsl:text>  Max Packet Size : </xsl:text>
		<xsl:choose>
			<xsl:when test="@maxPacketSize = 0">
				<xsl:text>Unlimited</xsl:text>
			</xsl:when>
			<xsl:otherwise>
				<xsl:value-of select="@maxPacketSize"/>
			</xsl:otherwise>
		</xsl:choose>
		<xsl:call-template name="PrintReturn"/>
		
		<xsl:text>     Capture File : </xsl:text>
		<xsl:value-of select="@captureFile"/>
		<xsl:call-template name="PrintReturn"/>

		<xsl:text>Capture File Size : </xsl:text>
		<xsl:value-of select="@captureFileSize"/>
		<xsl:call-template name="PrintReturn"/>

		<xsl:if test="EncryptionKey">
			<xsl:text>   Encryption Key : </xsl:text>
			<xsl:value-of select="EncryptionKey"/>
			<xsl:call-template name="PrintReturn"/>
		</xsl:if>
	</xsl:template>

	<xsl:template match="Filter">
		<!-- print adapter filter -->
		<xsl:apply-templates select="AdapterFilter"/>
		<xsl:call-template name="PrintReturn"/>

		<!-- print capture filter -->
		<xsl:text>Filter Length: </xsl:text>
		<xsl:value-of select="BpfFilter/@length"/>
		<xsl:call-template name="PrintReturn"/>
		<xsl:for-each select="BpfFilterInstructions/Instruction">
			<xsl:text> </xsl:text>
			<xsl:value-of select="format-number(position(), '0000')"/>
			<xsl:text> - </xsl:text>
			<xsl:value-of select="."/>
			<xsl:call-template name="PrintReturn"/>
		</xsl:for-each>
	</xsl:template>

	<xsl:template match="Success">
		<xsl:call-template name="PrintReturn"/>
		<xsl:text>Command completed successfully</xsl:text>
		<xsl:call-template name="PrintReturn"/>
	</xsl:template>

	<xsl:template match="AdapterFilter">
		<xsl:text>Adapter Filter: (</xsl:text>
		<xsl:value-of select="@value"/>
		<xsl:text>)</xsl:text>
		<xsl:call-template name="PrintReturn"/>

		<xsl:if test="NdisPacketTypeDirected">
			<xsl:text>    DIRECTED</xsl:text>
			<xsl:call-template name="PrintReturn"/>
		</xsl:if>
		<xsl:if test="NdisPacketTypeMulticast">
			<xsl:text>    MULTICAST</xsl:text>
			<xsl:call-template name="PrintReturn"/>
		</xsl:if>
		<xsl:if test="NdisPacketTypeAllMulticast">
			<xsl:text>    ALL MULTICAST</xsl:text>
			<xsl:call-template name="PrintReturn"/>
		</xsl:if>
		<xsl:if test="NdisPacketTypeBroadcast">
			<xsl:text>    BROADCAST</xsl:text>
			<xsl:call-template name="PrintReturn"/>
		</xsl:if>
		<xsl:if test="NdisPacketTypeSourceRouting">
			<xsl:text>    SOURCE ROUTING</xsl:text>
			<xsl:call-template name="PrintReturn"/>
		</xsl:if>
		<xsl:if test="NdisPacketTypePromiscuous">
			<xsl:text>    PROMISCUOUS</xsl:text>
			<xsl:call-template name="PrintReturn"/>
		</xsl:if>
		<xsl:if test="NdisPacketTypeSmt">
			<xsl:text>    SMT</xsl:text>
			<xsl:call-template name="PrintReturn"/>
		</xsl:if>
		<xsl:if test="NdisPacketTypeAllLocal">
			<xsl:text>    ALL LOCAL</xsl:text>
			<xsl:call-template name="PrintReturn"/>
		</xsl:if>
		<xsl:if test="NdisPacketTypeMacFrame">
			<xsl:text>    MAC FRAME</xsl:text>
			<xsl:call-template name="PrintReturn"/>
		</xsl:if>
		<xsl:if test="NdisPacketTypeFunctional">
			<xsl:text>    FUNCTIONAL</xsl:text>
			<xsl:call-template name="PrintReturn"/>
		</xsl:if>
		<xsl:if test="NdisPacketTypeAllFunctional">
			<xsl:text>    ALL FUNCTIONAL</xsl:text>
			<xsl:call-template name="PrintReturn"/>
		</xsl:if>
		<xsl:if test="NdisPacketTypeGroup">
			<xsl:text>    GROUP</xsl:text>
			<xsl:call-template name="PrintReturn"/>
		</xsl:if>
	</xsl:template>

</xsl:transform>